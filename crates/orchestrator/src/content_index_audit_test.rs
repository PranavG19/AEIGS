use crate::content_index_audit::*;

#[test]
fn no_content_index_no_issues() {
    assert!(analyze_content_index("<html><body>hello</body></html>").is_empty());
}

#[test]
fn detects_api_content_index() {
    let body = r#"<script>const idx = await registration.index;</script>"#;
    // This shouldn't match — no ContentIndex or contentIndex keyword
    assert!(analyze_content_index(body).is_empty());
}

#[test]
fn detects_api_explicit() {
    let body = r#"<script>const idx = registration.contentIndex;</script>"#;
    let issues = analyze_content_index(body);
    assert!(issues.contains(&ContentIndexIssue::ApiDetected));
}

#[test]
fn detects_silent_registration() {
    let body = r#"<script>
        const reg = await navigator.serviceWorker.ready;
        await reg.contentIndex.add({id: "1", title: "Page", url: "/page"});
    </script>"#;
    let issues = analyze_content_index(body);
    assert!(issues.contains(&ContentIndexIssue::SilentRegistration));
}

#[test]
fn no_silent_with_click() {
    let body = r#"<script>
        btn.addEventListener("click", async () => {
            const reg = await navigator.serviceWorker.ready;
            await reg.contentIndex.add({id: "1", title: "Page", url: "/page"});
        });
    </script>"#;
    let issues = analyze_content_index(body);
    assert!(!issues.contains(&ContentIndexIssue::SilentRegistration));
}

#[test]
fn detects_offline_injection() {
    let body = r#"<script>
        const reg = await navigator.serviceWorker.ready;
        await reg.contentIndex.add({id: "1", title: "Free", url: "http://evil.com/page"});
    </script>"#;
    let issues = analyze_content_index(body);
    assert!(issues.contains(&ContentIndexIssue::OfflineContentInjection));
}

#[test]
fn no_injection_with_https() {
    let body = r#"<script>
        const reg = await navigator.serviceWorker.ready;
        await reg.contentIndex.add({id: "1", title: "Safe", url: "/safe-page"});
    </script>"#;
    let issues = analyze_content_index(body);
    assert!(!issues.contains(&ContentIndexIssue::OfflineContentInjection));
}

#[test]
fn detects_phishing_content() {
    let body = r#"<script>
        const reg = await navigator.serviceWorker.ready;
        await reg.contentIndex.add({id: "1", title: "Login Required", url: "/login"});
    </script>"#;
    let issues = analyze_content_index(body);
    assert!(issues.contains(&ContentIndexIssue::PhishingContent));
}

#[test]
fn detects_excessive_entries() {
    let body = r#"<script>
        const reg = await navigator.serviceWorker.ready;
        items.forEach(item => reg.contentIndex.add({id: item.id, title: item.t, url: item.url}));
    </script>"#;
    let issues = analyze_content_index(body);
    assert!(issues.contains(&ContentIndexIssue::ExcessiveEntries));
}

#[test]
fn detects_index_enumeration() {
    let body = r#"<script>
        const reg = await navigator.serviceWorker.ready;
        const entries = await reg.contentIndex.getAll();
    </script>"#;
    let issues = analyze_content_index(body);
    assert!(issues.contains(&ContentIndexIssue::IndexEnumeration));
}

#[test]
fn no_enumeration_without_getall() {
    let body = r#"<script>
        const reg = await navigator.serviceWorker.ready;
        await reg.contentIndex.add({id: "1", title: "t", url: "/p"});
    </script>"#;
    let issues = analyze_content_index(body);
    assert!(!issues.contains(&ContentIndexIssue::IndexEnumeration));
}

#[test]
fn severity_phishing_highest() {
    assert_eq!(
        content_index_severity(&ContentIndexIssue::PhishingContent),
        7.5
    );
}

#[test]
fn severity_detected_lowest() {
    assert_eq!(content_index_severity(&ContentIndexIssue::ApiDetected), 2.5);
}

#[test]
fn to_operations_creates_entries() {
    let issues = vec![
        ContentIndexIssue::ApiDetected,
        ContentIndexIssue::IndexEnumeration,
    ];
    let mut seq = 0;
    let ops = content_index_to_operations(&issues, &mut seq);
    assert_eq!(ops.len(), 2);
    assert_eq!(seq, 2);
}

#[test]
fn display_variants() {
    assert_eq!(ContentIndexIssue::ApiDetected.to_string(), "api_detected");
    assert_eq!(
        ContentIndexIssue::OfflineContentInjection.to_string(),
        "offline_content_injection"
    );
    assert_eq!(
        ContentIndexIssue::IndexEnumeration.to_string(),
        "index_enumeration"
    );
    assert_eq!(
        ContentIndexIssue::PhishingContent.to_string(),
        "phishing_content"
    );
    assert_eq!(
        ContentIndexIssue::SilentRegistration.to_string(),
        "silent_registration"
    );
    assert_eq!(
        ContentIndexIssue::ExcessiveEntries.to_string(),
        "excessive_entries"
    );
}

#[test]
fn empty_body_no_issues() {
    assert!(analyze_content_index("").is_empty());
}
