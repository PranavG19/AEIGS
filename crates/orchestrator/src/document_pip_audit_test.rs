use crate::document_pip_audit::*;

#[test]
fn no_pip_no_issues() {
    assert!(analyze_document_pip("<html><body>hello</body></html>").is_empty());
}

#[test]
fn detects_document_pip_api() {
    let body = r#"<script>
        const pipWindow = await documentPictureInPicture.requestWindow();
    </script>"#;
    let issues = analyze_document_pip(body);
    assert!(issues.contains(&DocumentPipIssue::ApiDetected));
}

#[test]
fn detects_uppercase_api() {
    let body = r#"<script>
        if ('DocumentPictureInPicture' in window) { /* supported */ }
    </script>"#;
    let issues = analyze_document_pip(body);
    assert!(issues.contains(&DocumentPipIssue::ApiDetected));
}

#[test]
fn detects_ui_spoofing() {
    let body = r#"<script>
        const pipWindow = await documentPictureInPicture.requestWindow({
            width: 400, height: 300
        });
        pipWindow.moveTo(100, 100);
    </script>"#;
    let issues = analyze_document_pip(body);
    assert!(issues.contains(&DocumentPipIssue::UiSpoofing));
}

#[test]
fn no_spoofing_without_positioning() {
    let body = r#"<script>
        const pipWindow = await documentPictureInPicture.requestWindow({
            width: 400, height: 300
        });
    </script>"#;
    let issues = analyze_document_pip(body);
    assert!(!issues.contains(&DocumentPipIssue::UiSpoofing));
}

#[test]
fn detects_overlay_attack() {
    let body = r#"<script>
        const pipWindow = await documentPictureInPicture.requestWindow();
        pipWindow.document.body.style.zIndex = "99999";
        pipWindow.document.body.style.opacity = "0.01";
    </script>"#;
    let issues = analyze_document_pip(body);
    assert!(issues.contains(&DocumentPipIssue::OverlayAttack));
}

#[test]
fn no_overlay_without_transparency() {
    let body = r#"<script>
        const pipWindow = await documentPictureInPicture.requestWindow();
        pipWindow.document.body.style.zIndex = "10";
    </script>"#;
    let issues = analyze_document_pip(body);
    assert!(!issues.contains(&DocumentPipIssue::OverlayAttack));
}

#[test]
fn detects_content_injection() {
    let body = r#"<script>
        const pipWindow = await documentPictureInPicture.requestWindow();
        pipWindow.document.body.innerHTML = userContent;
    </script>"#;
    let issues = analyze_document_pip(body);
    assert!(issues.contains(&DocumentPipIssue::ContentInjection));
}

#[test]
fn no_injection_with_sanitize() {
    let body = r#"<script>
        const pipWindow = await documentPictureInPicture.requestWindow();
        pipWindow.document.body.innerHTML = sanitize(content);
    </script>"#;
    let issues = analyze_document_pip(body);
    assert!(!issues.contains(&DocumentPipIssue::ContentInjection));
}

#[test]
fn detects_persistent_window() {
    let body = r#"<script>
        const pipWindow = await documentPictureInPicture.requestWindow();
        setInterval(() => { pipWindow.document.title = "Alert!"; }, 1000);
    </script>"#;
    let issues = analyze_document_pip(body);
    assert!(issues.contains(&DocumentPipIssue::PersistentWindow));
}

#[test]
fn no_persistent_with_close() {
    let body = r#"<script>
        const pipWindow = await documentPictureInPicture.requestWindow();
        setInterval(() => { pipWindow.close(); }, 5000);
    </script>"#;
    let issues = analyze_document_pip(body);
    assert!(!issues.contains(&DocumentPipIssue::PersistentWindow));
}

#[test]
fn severity_injection_highest() {
    assert_eq!(
        document_pip_severity(&DocumentPipIssue::ContentInjection),
        7.5
    );
}

#[test]
fn severity_detected_lowest() {
    assert_eq!(document_pip_severity(&DocumentPipIssue::ApiDetected), 2.0);
}

#[test]
fn to_operations_creates_entries() {
    let issues = vec![DocumentPipIssue::ApiDetected, DocumentPipIssue::UiSpoofing];
    let mut seq = 0;
    let ops = document_pip_to_operations(&issues, &mut seq);
    assert_eq!(ops.len(), 2);
    assert_eq!(seq, 2);
}

#[test]
fn display_variants() {
    assert_eq!(DocumentPipIssue::ApiDetected.to_string(), "api_detected");
    assert_eq!(DocumentPipIssue::UiSpoofing.to_string(), "ui_spoofing");
    assert_eq!(
        DocumentPipIssue::OverlayAttack.to_string(),
        "overlay_attack"
    );
    assert_eq!(
        DocumentPipIssue::ContentInjection.to_string(),
        "content_injection"
    );
    assert_eq!(
        DocumentPipIssue::PersistentWindow.to_string(),
        "persistent_window"
    );
}

#[test]
fn empty_body_no_issues() {
    assert!(analyze_document_pip("").is_empty());
}
