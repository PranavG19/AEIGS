use crate::text_fragment_audit::*;

#[test]
fn empty_body() {
    let issues = analyze_text_fragment("");
    assert!(issues.is_empty());
}

#[test]
fn no_api() {
    let body = "<html><body><p>Hello world</p></body></html>";
    let issues = analyze_text_fragment(body);
    assert!(issues.is_empty());
}

#[test]
fn detects_text_fragment_hash() {
    let body = r#"<a href="https://example.com/page#:~:text=secret">link</a>"#;
    let issues = analyze_text_fragment(body);
    assert!(issues.contains(&TextFragmentIssue::ApiDetected));
}

#[test]
fn detects_fragment_directive() {
    let body = r#"<script>if (document.fragmentDirective) { console.log('supported'); }</script>"#;
    let issues = analyze_text_fragment(body);
    assert!(issues.contains(&TextFragmentIssue::ApiDetected));
}

#[test]
fn detects_text_fragment_api() {
    let body = r#"<script>if (window.TextFragment) { console.log('available'); }</script>"#;
    let issues = analyze_text_fragment(body);
    assert!(issues.contains(&TextFragmentIssue::ApiDetected));
}

#[test]
fn detects_content_exfiltration() {
    let body = concat!(
        "<script>\n",
        "  let target = 'page#:~:text=sensitive';\n",
        "  fetch('/collect?data=' + document.fragmentDirective);\n",
        "</script>",
    );
    let issues = analyze_text_fragment(body);
    assert!(issues.contains(&TextFragmentIssue::ContentExfiltration));
}

#[test]
fn no_exfiltration_without_network() {
    let body = r#"<a href="page#:~:text=hello">link</a>"#;
    let issues = analyze_text_fragment(body);
    assert!(!issues.contains(&TextFragmentIssue::ContentExfiltration));
}

#[test]
fn detects_cross_origin_leak() {
    let body = r#"<script>
        if (document.fragmentDirective) {
            let ref = document.referrer;
        }
    </script>"#;
    let issues = analyze_text_fragment(body);
    assert!(issues.contains(&TextFragmentIssue::CrossOriginLeak));
}

#[test]
fn no_leak_without_referrer() {
    let body = r#"<script>document.fragmentDirective; console.log('test');</script>"#;
    let issues = analyze_text_fragment(body);
    assert!(!issues.contains(&TextFragmentIssue::CrossOriginLeak));
}

#[test]
fn detects_privacy_violation() {
    let body = concat!(
        "<script>\n",
        "  let url = 'page#:~:text=data';\n",
        "  let observer = new IntersectionObserver(callback);\n",
        "  analytics.track('scroll');\n",
        "</script>",
    );
    let issues = analyze_text_fragment(body);
    assert!(issues.contains(&TextFragmentIssue::PrivacyViolation));
}

#[test]
fn no_privacy_without_tracking() {
    let body = concat!(
        "<script>\n",
        "  let url = 'page#:~:text=data';\n",
        "  let observer = new IntersectionObserver(callback);\n",
        "</script>",
    );
    let issues = analyze_text_fragment(body);
    assert!(!issues.contains(&TextFragmentIssue::PrivacyViolation));
}

#[test]
fn detects_phishing_amplification() {
    let body = concat!(
        "<script>\n",
        "  let link = 'page#:~:text=enter+your';\n",
        "  document.querySelector('a').href = link;\n",
        "  document.getElementById('password').focus();\n",
        "</script>",
    );
    let issues = analyze_text_fragment(body);
    assert!(issues.contains(&TextFragmentIssue::PhishingAmplification));
}

#[test]
fn no_phishing_without_credentials() {
    let body = concat!(
        "<script>\n",
        "  let link = 'page#:~:text=hello';\n",
        "  document.querySelector('a').href = link;\n",
        "</script>",
    );
    let issues = analyze_text_fragment(body);
    assert!(!issues.contains(&TextFragmentIssue::PhishingAmplification));
}

#[test]
fn all_issues_detected() {
    let body = concat!(
        "<script>\n",
        "  let url = 'page#:~:text=secret';\n",
        "  fetch('/exfil?d=' + document.fragmentDirective);\n",
        "  let ref = document.referrer;\n",
        "  let obs = new IntersectionObserver(cb);\n",
        "  analytics.track('view');\n",
        "  document.querySelector('a').href = url;\n",
        "  document.getElementById('password').focus();\n",
        "</script>",
    );
    let issues = analyze_text_fragment(body);
    assert_eq!(issues.len(), 5);
    assert!(issues.contains(&TextFragmentIssue::ApiDetected));
    assert!(issues.contains(&TextFragmentIssue::ContentExfiltration));
    assert!(issues.contains(&TextFragmentIssue::CrossOriginLeak));
    assert!(issues.contains(&TextFragmentIssue::PrivacyViolation));
    assert!(issues.contains(&TextFragmentIssue::PhishingAmplification));
}

#[test]
fn severity_values_correct() {
    assert_eq!(
        text_fragment_severity(&TextFragmentIssue::ContentExfiltration),
        7.0
    );
    assert_eq!(
        text_fragment_severity(&TextFragmentIssue::CrossOriginLeak),
        6.5
    );
    assert_eq!(
        text_fragment_severity(&TextFragmentIssue::PrivacyViolation),
        6.0
    );
    assert_eq!(
        text_fragment_severity(&TextFragmentIssue::PhishingAmplification),
        5.5
    );
    assert_eq!(text_fragment_severity(&TextFragmentIssue::ApiDetected), 2.0);
}

#[test]
fn display_impl_works() {
    assert_eq!(TextFragmentIssue::ApiDetected.to_string(), "api_detected");
    assert_eq!(
        TextFragmentIssue::ContentExfiltration.to_string(),
        "content_exfiltration"
    );
    assert_eq!(
        TextFragmentIssue::CrossOriginLeak.to_string(),
        "cross_origin_leak"
    );
}

#[test]
fn operations_generated_correctly() {
    let issues = vec![
        TextFragmentIssue::ApiDetected,
        TextFragmentIssue::ContentExfiltration,
    ];
    let mut seq = 0;
    let ops = text_fragment_to_operations(&issues, &mut seq);
    assert_eq!(ops.len(), 2);
    assert_eq!(seq, 2);
}

#[test]
fn operations_increment_sequence() {
    let issues = vec![
        TextFragmentIssue::ApiDetected,
        TextFragmentIssue::CrossOriginLeak,
        TextFragmentIssue::PrivacyViolation,
    ];
    let mut seq = 5;
    let ops = text_fragment_to_operations(&issues, &mut seq);
    assert_eq!(ops.len(), 3);
    assert_eq!(seq, 8);
}
