use crate::opener_audit::*;

// --- MissingNoopener detection ---

#[test]
fn detects_missing_noopener_on_blank_link() {
    let html = r#"<a href="https://example.com" target="_blank">Link</a>"#;
    let issues = find_opener_issues(html);
    assert!(issues.contains(&OpenerIssue::MissingNoopener {
        href: "https://example.com".into()
    }));
}

#[test]
fn noopener_present_suppresses_missing_noopener() {
    let html = r#"<a href="https://example.com" target="_blank" rel="noopener">Link</a>"#;
    let issues = find_opener_issues(html);
    assert!(
        !issues
            .iter()
            .any(|i| matches!(i, OpenerIssue::MissingNoopener { .. }))
    );
}

#[test]
fn noopener_only_still_emits_missing_noreferrer() {
    let html = r#"<a href="https://example.com" target="_blank" rel="noopener">Link</a>"#;
    let issues = find_opener_issues(html);
    assert!(issues.contains(&OpenerIssue::MissingNoreferrer {
        href: "https://example.com".into()
    }));
}

// --- MissingNoreferrer detection ---

#[test]
fn detects_missing_noreferrer_on_blank_link() {
    let html = r#"<a href="https://example.com" target="_blank">Link</a>"#;
    let issues = find_opener_issues(html);
    assert!(issues.contains(&OpenerIssue::MissingNoreferrer {
        href: "https://example.com".into()
    }));
}

#[test]
fn noreferrer_present_suppresses_missing_noreferrer() {
    let html = r#"<a href="https://example.com" target="_blank" rel="noreferrer">Link</a>"#;
    let issues = find_opener_issues(html);
    assert!(
        !issues
            .iter()
            .any(|i| matches!(i, OpenerIssue::MissingNoreferrer { .. }))
    );
}

#[test]
fn noreferrer_only_still_emits_missing_noopener() {
    let html = r#"<a href="https://example.com" target="_blank" rel="noreferrer">Link</a>"#;
    let issues = find_opener_issues(html);
    assert!(issues.contains(&OpenerIssue::MissingNoopener {
        href: "https://example.com".into()
    }));
}

#[test]
fn both_noopener_noreferrer_suppresses_both() {
    let html =
        r#"<a href="https://example.com" target="_blank" rel="noopener noreferrer">Link</a>"#;
    let issues = find_opener_issues(html);
    assert!(!issues.iter().any(|i| matches!(
        i,
        OpenerIssue::MissingNoopener { .. } | OpenerIssue::MissingNoreferrer { .. }
    )));
}

// --- ExternalLinkNoRel detection ---

#[test]
fn detects_external_link_no_rel() {
    let html = r#"<a href="https://example.com">Link</a>"#;
    let issues = find_opener_issues(html);
    assert!(issues.contains(&OpenerIssue::ExternalLinkNoRel {
        href: "https://example.com".into()
    }));
}

#[test]
fn external_link_with_rel_no_issue() {
    let html = r#"<a href="https://example.com" rel="nofollow">Link</a>"#;
    let issues = find_opener_issues(html);
    assert!(
        !issues
            .iter()
            .any(|i| matches!(i, OpenerIssue::ExternalLinkNoRel { .. }))
    );
}

#[test]
fn relative_link_no_rel_no_issue() {
    let html = r#"<a href="/about">About</a>"#;
    let issues = find_opener_issues(html);
    assert!(issues.is_empty());
}

// --- FormTargetBlank detection ---

#[test]
fn detects_form_target_blank_external_action() {
    let html = r#"<form action="https://evil.com/submit" target="_blank">"#;
    let issues = find_opener_issues(html);
    assert!(issues.contains(&OpenerIssue::FormTargetBlank {
        action: "https://evil.com/submit".into()
    }));
}

#[test]
fn form_target_blank_relative_action_no_issue() {
    let html = r#"<form action="/submit" target="_blank">"#;
    let issues = find_opener_issues(html);
    assert!(
        !issues
            .iter()
            .any(|i| matches!(i, OpenerIssue::FormTargetBlank { .. }))
    );
}

#[test]
fn form_without_target_blank_no_issue() {
    let html = r#"<form action="https://evil.com/submit">"#;
    let issues = find_opener_issues(html);
    assert!(
        !issues
            .iter()
            .any(|i| matches!(i, OpenerIssue::FormTargetBlank { .. }))
    );
}

// --- AreaTargetBlank detection ---

#[test]
fn detects_area_target_blank_without_noopener() {
    let html = r#"<area href="/map-region" target="_blank">"#;
    let issues = find_opener_issues(html);
    assert!(issues.contains(&OpenerIssue::AreaTargetBlank {
        href: "/map-region".into()
    }));
}

#[test]
fn area_target_blank_with_noopener_no_issue() {
    let html = r#"<area href="/region" target="_blank" rel="noopener">"#;
    let issues = find_opener_issues(html);
    assert!(
        !issues
            .iter()
            .any(|i| matches!(i, OpenerIssue::AreaTargetBlank { .. }))
    );
}

#[test]
fn area_without_target_blank_no_issue() {
    let html = r#"<area href="/region">"#;
    let issues = find_opener_issues(html);
    assert!(
        !issues
            .iter()
            .any(|i| matches!(i, OpenerIssue::AreaTargetBlank { .. }))
    );
}

// --- BaseTargetBlank detection ---

#[test]
fn detects_base_target_blank() {
    let html = r#"<base target="_blank">"#;
    let issues = find_opener_issues(html);
    assert!(issues.contains(&OpenerIssue::BaseTargetBlank));
}

#[test]
fn base_without_target_blank_no_issue() {
    let html = r#"<base href="/">"#;
    let issues = find_opener_issues(html);
    assert!(
        !issues
            .iter()
            .any(|i| matches!(i, OpenerIssue::BaseTargetBlank))
    );
}

// --- WindowOpenNoFeatures detection ---

#[test]
fn detects_window_open_no_features_in_script() {
    let html = r#"<script>window.open("https://example.com")</script>"#;
    let issues = find_opener_issues(html);
    assert!(
        issues
            .iter()
            .any(|i| matches!(i, OpenerIssue::WindowOpenNoFeatures { .. }))
    );
}

#[test]
fn window_open_with_features_no_issue() {
    let html = r#"<script>window.open("https://x.com", "_blank", "noopener")</script>"#;
    let issues = find_opener_issues(html);
    assert!(
        !issues
            .iter()
            .any(|i| matches!(i, OpenerIssue::WindowOpenNoFeatures { .. }))
    );
}

#[test]
fn window_open_with_two_args_no_features() {
    let html = r#"<script>window.open("https://x.com", "_blank")</script>"#;
    let issues = find_opener_issues(html);
    assert!(
        issues
            .iter()
            .any(|i| matches!(i, OpenerIssue::WindowOpenNoFeatures { .. }))
    );
}

// --- JavascriptWindowOpen detection ---

#[test]
fn detects_javascript_window_open_href() {
    let html = r#"<a href="javascript:window.open('https://evil.com')">Click</a>"#;
    let issues = find_opener_issues(html);
    assert!(issues.contains(&OpenerIssue::JavascriptWindowOpen));
}

#[test]
fn javascript_href_without_window_open_no_issue() {
    let html = r#"<a href="javascript:void(0)">Click</a>"#;
    let issues = find_opener_issues(html);
    assert!(
        !issues
            .iter()
            .any(|i| matches!(i, OpenerIssue::JavascriptWindowOpen))
    );
}

// --- UserContentLink detection ---

#[test]
fn detects_user_content_link_url_param() {
    let html = r#"<a href="https://example.com/redir?url=https://evil.com">Go</a>"#;
    let issues = find_opener_issues(html);
    assert!(
        issues
            .iter()
            .any(|i| matches!(i, OpenerIssue::UserContentLink { .. }))
    );
}

#[test]
fn detects_user_content_link_redirect_param() {
    let html = r#"<a href="https://example.com/out?redirect=https://evil.com">Go</a>"#;
    let issues = find_opener_issues(html);
    assert!(
        issues
            .iter()
            .any(|i| matches!(i, OpenerIssue::UserContentLink { .. }))
    );
}

#[test]
fn external_link_without_user_params_no_user_content() {
    let html = r#"<a href="https://example.com/page">Go</a>"#;
    let issues = find_opener_issues(html);
    assert!(
        !issues
            .iter()
            .any(|i| matches!(i, OpenerIssue::UserContentLink { .. }))
    );
}

// --- Display tests ---

#[test]
fn display_missing_noopener() {
    let issue = OpenerIssue::MissingNoopener {
        href: "https://x.com".into(),
    };
    assert_eq!(issue.to_string(), "missing_noopener:https://x.com");
}

#[test]
fn display_missing_noreferrer() {
    let issue = OpenerIssue::MissingNoreferrer {
        href: "https://x.com".into(),
    };
    assert_eq!(issue.to_string(), "missing_noreferrer:https://x.com");
}

#[test]
fn display_form_target_blank() {
    let issue = OpenerIssue::FormTargetBlank {
        action: "https://evil.com".into(),
    };
    assert_eq!(issue.to_string(), "form_target_blank:https://evil.com");
}

#[test]
fn display_area_target_blank() {
    let issue = OpenerIssue::AreaTargetBlank {
        href: "/region".into(),
    };
    assert_eq!(issue.to_string(), "area_target_blank:/region");
}

#[test]
fn display_base_target_blank() {
    assert_eq!(
        OpenerIssue::BaseTargetBlank.to_string(),
        "base_target_blank"
    );
}

#[test]
fn display_window_open_no_features() {
    let issue = OpenerIssue::WindowOpenNoFeatures {
        context: "snippet".into(),
    };
    assert_eq!(issue.to_string(), "window_open_no_features:snippet");
}

#[test]
fn display_javascript_window_open() {
    assert_eq!(
        OpenerIssue::JavascriptWindowOpen.to_string(),
        "javascript_window_open"
    );
}

#[test]
fn display_external_link_no_rel() {
    let issue = OpenerIssue::ExternalLinkNoRel {
        href: "https://x.com".into(),
    };
    assert_eq!(issue.to_string(), "external_link_no_rel:https://x.com");
}

#[test]
fn display_user_content_link() {
    let issue = OpenerIssue::UserContentLink {
        href: "https://x.com?url=y".into(),
    };
    assert_eq!(issue.to_string(), "user_content_link:https://x.com?url=y");
}

// --- Severity tests ---

#[test]
fn severity_missing_noopener() {
    let s = opener_severity(&OpenerIssue::MissingNoopener {
        href: String::new(),
    });
    assert!((s - 3.5).abs() < f64::EPSILON);
}

#[test]
fn severity_missing_noreferrer() {
    let s = opener_severity(&OpenerIssue::MissingNoreferrer {
        href: String::new(),
    });
    assert!((s - 2.5).abs() < f64::EPSILON);
}

#[test]
fn severity_form_target_blank() {
    let s = opener_severity(&OpenerIssue::FormTargetBlank {
        action: String::new(),
    });
    assert!((s - 3.0).abs() < f64::EPSILON);
}

#[test]
fn severity_area_target_blank() {
    let s = opener_severity(&OpenerIssue::AreaTargetBlank {
        href: String::new(),
    });
    assert!((s - 3.0).abs() < f64::EPSILON);
}

#[test]
fn severity_base_target_blank() {
    let s = opener_severity(&OpenerIssue::BaseTargetBlank);
    assert!((s - 2.0).abs() < f64::EPSILON);
}

#[test]
fn severity_window_open_no_features() {
    let s = opener_severity(&OpenerIssue::WindowOpenNoFeatures {
        context: String::new(),
    });
    assert!((s - 3.5).abs() < f64::EPSILON);
}

#[test]
fn severity_javascript_window_open() {
    let s = opener_severity(&OpenerIssue::JavascriptWindowOpen);
    assert!((s - 4.0).abs() < f64::EPSILON);
}

#[test]
fn severity_external_link_no_rel() {
    let s = opener_severity(&OpenerIssue::ExternalLinkNoRel {
        href: String::new(),
    });
    assert!((s - 2.0).abs() < f64::EPSILON);
}

#[test]
fn severity_user_content_link() {
    let s = opener_severity(&OpenerIssue::UserContentLink {
        href: String::new(),
    });
    assert!((s - 4.5).abs() < f64::EPSILON);
}

// --- Operations tests ---

#[test]
fn operations_empty_when_no_issues() {
    let mut seq = 0;
    let ops = opener_to_operations(&[], &mut seq);
    assert!(ops.is_empty());
    assert_eq!(seq, 0);
}

#[test]
fn operations_one_per_issue() {
    let issues = vec![
        OpenerIssue::MissingNoopener {
            href: "https://a.com".into(),
        },
        OpenerIssue::FormTargetBlank {
            action: "https://b.com".into(),
        },
    ];
    let mut seq = 0;
    let ops = opener_to_operations(&issues, &mut seq);
    assert_eq!(ops.len(), 2);
    assert_eq!(seq, 2);
}

#[test]
fn operations_sequence_increments() {
    let issues = vec![
        OpenerIssue::BaseTargetBlank,
        OpenerIssue::JavascriptWindowOpen,
        OpenerIssue::ExternalLinkNoRel {
            href: "https://c.com".into(),
        },
    ];
    let mut seq = 5;
    let ops = opener_to_operations(&issues, &mut seq);
    assert_eq!(ops.len(), 3);
    assert_eq!(seq, 8);
    assert_eq!(ops[0].sequence_number, 6);
    assert_eq!(ops[1].sequence_number, 7);
    assert_eq!(ops[2].sequence_number, 8);
}

// --- Edge cases ---

#[test]
fn no_issues_in_empty_html() {
    let issues = find_opener_issues("");
    assert!(issues.is_empty());
}

#[test]
fn no_issues_in_linkless_html() {
    let html = r#"<html><body><p>No links</p></body></html>"#;
    let issues = find_opener_issues(html);
    assert!(issues.is_empty());
}

#[test]
fn only_internal_links_no_issues() {
    let html = r#"
        <a href="/about" target="_blank">About</a>
        <a href="/contact">Contact</a>
    "#;
    let issues = find_opener_issues(html);
    assert!(issues.is_empty());
}

#[test]
fn mixed_safe_and_unsafe_links() {
    let html = r#"
        <a href="https://safe.com" target="_blank" rel="noopener noreferrer">Safe</a>
        <a href="https://unsafe.com" target="_blank">Unsafe</a>
    "#;
    let issues = find_opener_issues(html);
    let noopener_count = issues
        .iter()
        .filter(
            |i| matches!(i, OpenerIssue::MissingNoopener { href } if href == "https://unsafe.com"),
        )
        .count();
    assert_eq!(noopener_count, 1);
}

#[test]
fn http_link_treated_as_external() {
    let html = r#"<a href="http://example.com" target="_blank">Link</a>"#;
    let issues = find_opener_issues(html);
    assert!(issues.contains(&OpenerIssue::MissingNoopener {
        href: "http://example.com".into()
    }));
}

#[test]
fn multiple_forms_mixed() {
    let html = r#"
        <form action="https://ext.com/pay" target="_blank">
        <form action="/local" target="_blank">
    "#;
    let issues = find_opener_issues(html);
    let form_issues: Vec<_> = issues
        .iter()
        .filter(|i| matches!(i, OpenerIssue::FormTargetBlank { .. }))
        .collect();
    assert_eq!(form_issues.len(), 1);
}

#[test]
fn user_content_link_with_ampersand_url() {
    let html = r#"<a href="https://example.com/page?id=1&url=https://evil.com">Go</a>"#;
    let issues = find_opener_issues(html);
    assert!(
        issues
            .iter()
            .any(|i| matches!(i, OpenerIssue::UserContentLink { .. }))
    );
}

#[test]
fn blank_link_emits_both_missing_noopener_and_noreferrer() {
    let html = r#"<a href="https://example.com" target="_blank">Link</a>"#;
    let issues = find_opener_issues(html);
    assert!(issues.contains(&OpenerIssue::MissingNoopener {
        href: "https://example.com".into()
    }));
    assert!(issues.contains(&OpenerIssue::MissingNoreferrer {
        href: "https://example.com".into()
    }));
}
