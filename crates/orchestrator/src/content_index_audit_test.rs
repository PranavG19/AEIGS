use super::*;

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

// ========== ContentIndexSecurityIssue Tests ==========

#[test]
fn test_empty_body_no_security_issues() {
    assert!(analyze_content_index_security("").is_empty());
}

#[test]
fn test_no_content_index_no_security_issues() {
    let body = "<html><body>hello world</body></html>";
    assert!(analyze_content_index_security(body).is_empty());
}

// IndexDataExfiltration tests
#[test]
fn test_index_data_exfiltration_positive() {
    let body = r#"<script>
        const data = await fetch('/api/user');
        await registration.index.add({id: '1', title: 'User', url: '/user'});
    </script>"#;
    let issues = analyze_content_index_security(body);
    assert!(issues.contains(&ContentIndexSecurityIssue::IndexDataExfiltration));
}

#[test]
fn test_index_data_exfiltration_xmlhttprequest() {
    let body = r#"<script>
        const xhr = new XMLHttpRequest();
        xhr.open('GET', '/data');
        await registration.index.add({id: '1', title: 'Data', url: '/data'});
    </script>"#;
    let issues = analyze_content_index_security(body);
    assert!(issues.contains(&ContentIndexSecurityIssue::IndexDataExfiltration));
}

#[test]
fn test_index_data_exfiltration_negative_no_fetch() {
    let body = r#"<script>
        await registration.index.add({id: '1', title: 'Static', url: '/page'});
    </script>"#;
    let issues = analyze_content_index_security(body);
    assert!(!issues.contains(&ContentIndexSecurityIssue::IndexDataExfiltration));
}

#[test]
fn test_index_data_exfiltration_negative_no_add() {
    let body = r#"<script>
        const data = await fetch('/api/user');
        console.log(data);
    </script>"#;
    let issues = analyze_content_index_security(body);
    assert!(!issues.contains(&ContentIndexSecurityIssue::IndexDataExfiltration));
}

// IndexEnumeration tests
#[test]
fn test_index_enumeration_positive() {
    let body = r#"<script>
        const entries = await registration.index.getAll();
        console.log(entries);
    </script>"#;
    let issues = analyze_content_index_security(body);
    assert!(issues.contains(&ContentIndexSecurityIssue::IndexEnumeration));
}

#[test]
fn test_index_enumeration_positive_simple() {
    let body = r#"<script>
        const all = await index.getAll();
    </script>"#;
    let issues = analyze_content_index_security(body);
    assert!(issues.contains(&ContentIndexSecurityIssue::IndexEnumeration));
}

#[test]
fn test_index_enumeration_negative() {
    let body = r#"<script>
        await registration.index.add({id: '1', title: 'T', url: '/p'});
    </script>"#;
    let issues = analyze_content_index_security(body);
    assert!(!issues.contains(&ContentIndexSecurityIssue::IndexEnumeration));
}

// IndexWithoutConsent tests
#[test]
fn test_index_without_consent_positive() {
    let body = r#"<script>
        window.addEventListener('load', async () => {
            await registration.index.add({id: '1', title: 'T', url: '/p'});
        });
    </script>"#;
    let issues = analyze_content_index_security(body);
    assert!(issues.contains(&ContentIndexSecurityIssue::IndexWithoutConsent));
}

#[test]
fn test_index_without_consent_negative_with_click() {
    let body = r#"<script>
        button.addEventListener('click', async () => {
            await registration.index.add({id: '1', title: 'T', url: '/p'});
        });
    </script>"#;
    let issues = analyze_content_index_security(body);
    assert!(!issues.contains(&ContentIndexSecurityIssue::IndexWithoutConsent));
}

#[test]
fn test_index_without_consent_negative_with_submit() {
    let body = r#"<script>
        form.addEventListener('submit', async () => {
            await registration.index.add({id: '1', title: 'T', url: '/p'});
        });
    </script>"#;
    let issues = analyze_content_index_security(body);
    assert!(!issues.contains(&ContentIndexSecurityIssue::IndexWithoutConsent));
}

#[test]
fn test_index_without_consent_negative_with_touchstart() {
    let body = r#"<script>
        elem.addEventListener('touchstart', async () => {
            await registration.index.add({id: '1', title: 'T', url: '/p'});
        });
    </script>"#;
    let issues = analyze_content_index_security(body);
    assert!(!issues.contains(&ContentIndexSecurityIssue::IndexWithoutConsent));
}

// IndexSensitiveContent tests
#[test]
fn test_index_sensitive_content_password() {
    let body = r#"<script>
        await registration.index.add({
            id: '1',
            title: 'Reset password',
            url: '/reset'
        });
    </script>"#;
    let issues = analyze_content_index_security(body);
    assert!(issues.contains(&ContentIndexSecurityIssue::IndexSensitiveContent));
}

#[test]
fn test_index_sensitive_content_token() {
    let body = r#"<script>
        await registration.index.add({
            id: '1',
            title: 'Auth token page',
            url: '/auth'
        });
    </script>"#;
    let issues = analyze_content_index_security(body);
    assert!(issues.contains(&ContentIndexSecurityIssue::IndexSensitiveContent));
}

#[test]
fn test_index_sensitive_content_api_key() {
    let body = r#"<script>
        await registration.index.add({
            id: '1',
            title: 'Get apiKey',
            url: '/keys'
        });
    </script>"#;
    let issues = analyze_content_index_security(body);
    assert!(issues.contains(&ContentIndexSecurityIssue::IndexSensitiveContent));
}

#[test]
fn test_index_sensitive_content_negative() {
    let body = r#"<script>
        await registration.index.add({
            id: '1',
            title: 'Public article',
            url: '/article'
        });
    </script>"#;
    let issues = analyze_content_index_security(body);
    assert!(!issues.contains(&ContentIndexSecurityIssue::IndexSensitiveContent));
}

// IndexCrossOrigin tests
#[test]
fn test_index_cross_origin_postmessage() {
    let body = r#"<script>
        window.addEventListener('message', async (e) => {
            const reg = await navigator.serviceWorker.ready;
            await reg.index.add({id: e.data.id, title: e.data.title, url: e.data.url});
        });
    </script>"#;
    let issues = analyze_content_index_security(body);
    assert!(issues.contains(&ContentIndexSecurityIssue::IndexCrossOrigin));
}

#[test]
fn test_index_cross_origin_iframe_with_getall() {
    let body = r#"<script>
        const iframe = document.createElement('iframe');
        const entries = await registration.index.getAll();
    </script>"#;
    let issues = analyze_content_index_security(body);
    assert!(issues.contains(&ContentIndexSecurityIssue::IndexCrossOrigin));
}

#[test]
fn test_index_cross_origin_negative_no_postmessage() {
    let body = r#"<script>
        await registration.index.add({id: '1', title: 'T', url: '/p'});
    </script>"#;
    let issues = analyze_content_index_security(body);
    assert!(!issues.contains(&ContentIndexSecurityIssue::IndexCrossOrigin));
}

// IndexPersistentTracking tests
#[test]
fn test_index_persistent_tracking_localstorage() {
    let body = r#"<script>
        const userId = localStorage.getItem('userId');
        await registration.index.add({id: userId, title: 'User', url: '/user'});
    </script>"#;
    let issues = analyze_content_index_security(body);
    assert!(issues.contains(&ContentIndexSecurityIssue::IndexPersistentTracking));
}

#[test]
fn test_index_persistent_tracking_sessionstorage() {
    let body = r#"<script>
        const sessionId = sessionStorage.getItem('session');
        await registration.index.getAll();
    </script>"#;
    let issues = analyze_content_index_security(body);
    assert!(issues.contains(&ContentIndexSecurityIssue::IndexPersistentTracking));
}

#[test]
fn test_index_persistent_tracking_negative() {
    let body = r#"<script>
        await registration.index.add({id: '1', title: 'T', url: '/p'});
    </script>"#;
    let issues = analyze_content_index_security(body);
    assert!(!issues.contains(&ContentIndexSecurityIssue::IndexPersistentTracking));
}

// IndexOverwrite tests
#[test]
fn test_index_overwrite_positive() {
    let body = r#"<script>
        await registration.index.delete('article-1');
        await registration.index.add({id: 'article-1', title: 'Malicious', url: '/phishing'});
    </script>"#;
    let issues = analyze_content_index_security(body);
    assert!(issues.contains(&ContentIndexSecurityIssue::IndexOverwrite));
}

#[test]
fn test_index_overwrite_negative_only_delete() {
    let body = r#"<script>
        await registration.index.delete('article-1');
    </script>"#;
    let issues = analyze_content_index_security(body);
    assert!(!issues.contains(&ContentIndexSecurityIssue::IndexOverwrite));
}

#[test]
fn test_index_overwrite_negative_only_add() {
    let body = r#"<script>
        await registration.index.add({id: '1', title: 'T', url: '/p'});
    </script>"#;
    let issues = analyze_content_index_security(body);
    assert!(!issues.contains(&ContentIndexSecurityIssue::IndexOverwrite));
}

// IndexInBackground tests
#[test]
fn test_index_in_background_positive() {
    let body = r#"<script>
        document.addEventListener('visibilitychange', async () => {
            if (document.hidden) {
                await registration.index.add({id: '1', title: 'Background', url: '/bg'});
            }
        });
    </script>"#;
    let issues = analyze_content_index_security(body);
    assert!(issues.contains(&ContentIndexSecurityIssue::IndexInBackground));
}

#[test]
fn test_index_in_background_with_delete() {
    let body = r#"<script>
        document.addEventListener('visibilitychange', async () => {
            await registration.index.delete('1');
        });
    </script>"#;
    let issues = analyze_content_index_security(body);
    assert!(issues.contains(&ContentIndexSecurityIssue::IndexInBackground));
}

#[test]
fn test_index_in_background_negative() {
    let body = r#"<script>
        await registration.index.add({id: '1', title: 'T', url: '/p'});
    </script>"#;
    let issues = analyze_content_index_security(body);
    assert!(!issues.contains(&ContentIndexSecurityIssue::IndexInBackground));
}

// ExcessiveIndexEntries tests
#[test]
fn test_excessive_index_entries_for_loop() {
    let body = r#"<script>
        for (let i = 0; i < 100; i++) {
            await registration.index.add({id: `${i}`, title: `Item ${i}`, url: `/item/${i}`});
        }
    </script>"#;
    let issues = analyze_content_index_security(body);
    assert!(issues.contains(&ContentIndexSecurityIssue::ExcessiveIndexEntries));
}

#[test]
fn test_excessive_index_entries_foreach() {
    let body = r#"<script>
        items.forEach(async (item) => {
            await registration.index.add({id: item.id, title: item.title, url: item.url});
        });
    </script>"#;
    let issues = analyze_content_index_security(body);
    assert!(issues.contains(&ContentIndexSecurityIssue::ExcessiveIndexEntries));
}

#[test]
fn test_excessive_index_entries_map() {
    let body = r#"<script>
        items.map(item => registration.index.add({id: item.id, title: item.title, url: item.url}));
    </script>"#;
    let issues = analyze_content_index_security(body);
    assert!(issues.contains(&ContentIndexSecurityIssue::ExcessiveIndexEntries));
}

#[test]
fn test_excessive_index_entries_while() {
    let body = r#"<script>
        while (hasMore) {
            await registration.index.add({id: getId(), title: 'T', url: '/p'});
        }
    </script>"#;
    let issues = analyze_content_index_security(body);
    assert!(issues.contains(&ContentIndexSecurityIssue::ExcessiveIndexEntries));
}

#[test]
fn test_excessive_index_entries_negative() {
    let body = r#"<script>
        await registration.index.add({id: '1', title: 'T', url: '/p'});
    </script>"#;
    let issues = analyze_content_index_security(body);
    assert!(!issues.contains(&ContentIndexSecurityIssue::ExcessiveIndexEntries));
}

// IndexWithoutServiceWorker tests
#[test]
fn test_index_without_service_worker_positive() {
    let body = r#"<script>
        const idx = window.contentIndex;
        await index.add({id: '1', title: 'T', url: '/p'});
    </script>"#;
    let issues = analyze_content_index_security(body);
    assert!(issues.contains(&ContentIndexSecurityIssue::IndexWithoutServiceWorker));
}

#[test]
fn test_index_without_service_worker_negative_has_serviceworker() {
    let body = r#"<script>
        const reg = await navigator.serviceWorker.ready;
        await reg.index.add({id: '1', title: 'T', url: '/p'});
    </script>"#;
    let issues = analyze_content_index_security(body);
    assert!(!issues.contains(&ContentIndexSecurityIssue::IndexWithoutServiceWorker));
}

#[test]
fn test_index_without_service_worker_negative_has_registration() {
    let body = r#"<script>
        await registration.index.add({id: '1', title: 'T', url: '/p'});
    </script>"#;
    let issues = analyze_content_index_security(body);
    assert!(!issues.contains(&ContentIndexSecurityIssue::IndexWithoutServiceWorker));
}

// Display trait tests
#[test]
fn test_display_trait() {
    assert_eq!(
        ContentIndexSecurityIssue::IndexDataExfiltration.to_string(),
        "index_data_exfiltration"
    );
    assert_eq!(
        ContentIndexSecurityIssue::IndexEnumeration.to_string(),
        "index_enumeration"
    );
    assert_eq!(
        ContentIndexSecurityIssue::IndexWithoutConsent.to_string(),
        "index_without_consent"
    );
    assert_eq!(
        ContentIndexSecurityIssue::IndexSensitiveContent.to_string(),
        "index_sensitive_content"
    );
    assert_eq!(
        ContentIndexSecurityIssue::IndexCrossOrigin.to_string(),
        "index_cross_origin"
    );
    assert_eq!(
        ContentIndexSecurityIssue::IndexPersistentTracking.to_string(),
        "index_persistent_tracking"
    );
    assert_eq!(
        ContentIndexSecurityIssue::IndexOverwrite.to_string(),
        "index_overwrite"
    );
    assert_eq!(
        ContentIndexSecurityIssue::IndexInBackground.to_string(),
        "index_in_background"
    );
    assert_eq!(
        ContentIndexSecurityIssue::ExcessiveIndexEntries.to_string(),
        "excessive_index_entries"
    );
    assert_eq!(
        ContentIndexSecurityIssue::IndexWithoutServiceWorker.to_string(),
        "index_without_service_worker"
    );
}

// Severity tests
#[test]
fn test_severity_range() {
    let variants = vec![
        ContentIndexSecurityIssue::IndexDataExfiltration,
        ContentIndexSecurityIssue::IndexEnumeration,
        ContentIndexSecurityIssue::IndexWithoutConsent,
        ContentIndexSecurityIssue::IndexSensitiveContent,
        ContentIndexSecurityIssue::IndexCrossOrigin,
        ContentIndexSecurityIssue::IndexPersistentTracking,
        ContentIndexSecurityIssue::IndexOverwrite,
        ContentIndexSecurityIssue::IndexInBackground,
        ContentIndexSecurityIssue::ExcessiveIndexEntries,
        ContentIndexSecurityIssue::IndexWithoutServiceWorker,
    ];

    for variant in variants {
        let severity = content_index_security_severity(&variant);
        assert!(
            severity >= 3.0 && severity <= 9.0,
            "Severity {} out of range for {:?}",
            severity,
            variant
        );
    }
}

#[test]
fn test_severity_highest() {
    assert_eq!(
        content_index_security_severity(&ContentIndexSecurityIssue::IndexDataExfiltration),
        9.0
    );
}

#[test]
fn test_severity_lowest() {
    assert_eq!(
        content_index_security_severity(&ContentIndexSecurityIssue::IndexWithoutServiceWorker),
        3.0
    );
}

// Operations generation tests
#[test]
fn test_operations_generation() {
    let issues = vec![
        ContentIndexSecurityIssue::IndexDataExfiltration,
        ContentIndexSecurityIssue::IndexEnumeration,
        ContentIndexSecurityIssue::IndexSensitiveContent,
    ];
    let mut seq = 0;
    let ops = content_index_security_to_operations(&issues, &mut seq);

    assert_eq!(ops.len(), 3);
    assert_eq!(seq, 3);
}

#[test]
fn test_operations_empty() {
    let issues = vec![];
    let mut seq = 0;
    let ops = content_index_security_to_operations(&issues, &mut seq);

    assert_eq!(ops.len(), 0);
    assert_eq!(seq, 0);
}

// Multiple issues test
#[test]
fn test_multiple_security_issues() {
    let body = r#"<script>
        const data = await fetch('/api/user');
        const userId = localStorage.getItem('userId');

        for (let i = 0; i < 10; i++) {
            await registration.index.add({
                id: `${userId}-${i}`,
                title: 'User password reset',
                url: `/reset/${i}`
            });
        }

        window.postMessage({entries: await registration.index.getAll()}, '*');
    </script>"#;

    let issues = analyze_content_index_security(body);

    assert!(issues.contains(&ContentIndexSecurityIssue::IndexDataExfiltration));
    assert!(issues.contains(&ContentIndexSecurityIssue::IndexEnumeration));
    assert!(issues.contains(&ContentIndexSecurityIssue::IndexSensitiveContent));
    assert!(issues.contains(&ContentIndexSecurityIssue::IndexCrossOrigin));
    assert!(issues.contains(&ContentIndexSecurityIssue::IndexPersistentTracking));
    assert!(issues.contains(&ContentIndexSecurityIssue::ExcessiveIndexEntries));
    assert!(issues.len() >= 6);
}
