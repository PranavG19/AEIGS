use crate::pip_audit::*;

#[test]
fn no_pip_no_issues() {
    assert!(analyze_pip("<html></html>").is_empty());
}

#[test]
fn detects_pip_request() {
    let body = r#"<script>video.requestPictureInPicture()</script>"#;
    let issues = analyze_pip(body);
    assert!(issues.contains(&PipIssue::PipRequested));
}

#[test]
fn detects_document_pip() {
    let body = r#"<script>documentPictureInPicture.requestWindow()</script>"#;
    let issues = analyze_pip(body);
    assert!(issues.contains(&PipIssue::DocumentPip));
}

#[test]
fn detects_auto_pip_attribute() {
    let body = r#"<video autopictureinpicture></video>"#;
    let issues = analyze_pip(body);
    assert!(issues.contains(&PipIssue::AutoPipAttribute));
}

#[test]
fn detects_pip_window_access() {
    let body = r#"<script>
        video.requestPictureInPicture();
        const pipWindow = video.pictureInPictureWindow;
    </script>"#;
    let issues = analyze_pip(body);
    assert!(issues.contains(&PipIssue::PipWindowAccess));
}

#[test]
fn detects_overlay_attack() {
    let body = r#"<script>
        const pip = await documentPictureInPicture.requestWindow();
        const el = document.createElement("div");
        pip.window.document.body.appendChild(el);
    </script>"#;
    let issues = analyze_pip(body);
    assert!(issues.contains(&PipIssue::OverlayAttack));
}

#[test]
fn detects_no_user_activation() {
    let body = r#"<script>video.requestPictureInPicture()</script>"#;
    let issues = analyze_pip(body);
    assert!(issues.contains(&PipIssue::NoUserActivation));
}

#[test]
fn no_activation_issue_with_click() {
    let body = r#"<script>
        btn.addEventListener("click", () => video.requestPictureInPicture());
    </script>"#;
    let issues = analyze_pip(body);
    assert!(!issues.contains(&PipIssue::NoUserActivation));
}

#[test]
fn severity_overlay_highest() {
    assert_eq!(pip_severity(&PipIssue::OverlayAttack), 6.5);
}

#[test]
fn severity_requested_lowest() {
    assert_eq!(pip_severity(&PipIssue::PipRequested), 3.0);
}

#[test]
fn to_operations_creates_entries() {
    let issues = vec![PipIssue::PipRequested, PipIssue::OverlayAttack];
    let mut seq = 0;
    let ops = pip_to_operations(&issues, &mut seq);
    assert_eq!(ops.len(), 2);
    assert_eq!(seq, 2);
}

#[test]
fn display_variants() {
    assert_eq!(PipIssue::PipRequested.to_string(), "pip_requested");
    assert_eq!(PipIssue::DocumentPip.to_string(), "document_pip");
    assert_eq!(PipIssue::AutoPipAttribute.to_string(), "auto_pip_attribute");
    assert_eq!(PipIssue::PipWindowAccess.to_string(), "pip_window_access");
    assert_eq!(PipIssue::OverlayAttack.to_string(), "overlay_attack");
    assert_eq!(PipIssue::NoUserActivation.to_string(), "no_user_activation");
}

#[test]
fn empty_body_no_issues() {
    assert!(analyze_pip("").is_empty());
}
