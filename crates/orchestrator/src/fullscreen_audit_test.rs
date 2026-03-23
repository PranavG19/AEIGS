use crate::fullscreen_audit::*;

#[test]
fn no_fullscreen_no_issues() {
    assert!(analyze_fullscreen("<html><body>hello</body></html>").is_empty());
}

#[test]
fn detects_api() {
    let body = r#"<script>el.requestFullscreen();</script>"#;
    let issues = analyze_fullscreen(body);
    assert!(issues.contains(&FullscreenIssue::ApiDetected));
}

#[test]
fn detects_webkit_variant() {
    let body = r#"<script>el.webkitRequestFullscreen();</script>"#;
    assert!(analyze_fullscreen(body).contains(&FullscreenIssue::ApiDetected));
}

#[test]
fn detects_no_user_activation() {
    let body = r#"<script>el.requestFullscreen();</script>"#;
    let issues = analyze_fullscreen(body);
    assert!(issues.contains(&FullscreenIssue::NoUserActivation));
}

#[test]
fn no_activation_issue_with_click() {
    let body = r#"<script>
        btn.addEventListener("click", () => el.requestFullscreen());
    </script>"#;
    let issues = analyze_fullscreen(body);
    assert!(!issues.contains(&FullscreenIssue::NoUserActivation));
}

#[test]
fn detects_fake_ui_overlay() {
    let body = r#"<script>
        el.requestFullscreen();
        document.createElement("div");
    </script>"#;
    let issues = analyze_fullscreen(body);
    assert!(issues.contains(&FullscreenIssue::FakeUiOverlay));
}

#[test]
fn detects_keyboard_lock() {
    let body = r#"<script>
        el.addEventListener("click", async () => {
            await el.requestFullscreen();
            navigator.keyboard.lock(["Escape"]);
        });
    </script>"#;
    let issues = analyze_fullscreen(body);
    assert!(issues.contains(&FullscreenIssue::KeyboardLock));
}

#[test]
fn detects_pointer_lock() {
    let body = r#"<script>
        el.addEventListener("click", () => {
            el.requestFullscreen();
            el.requestPointerLock();
        });
    </script>"#;
    let issues = analyze_fullscreen(body);
    assert!(issues.contains(&FullscreenIssue::PointerLock));
}

#[test]
fn detects_auto_fullscreen() {
    let body = r#"<script>
        document.addEventListener("DOMContentLoaded", () => {
            document.body.requestFullscreen();
        });
    </script>"#;
    let issues = analyze_fullscreen(body);
    assert!(issues.contains(&FullscreenIssue::AutoFullscreen));
}

#[test]
fn detects_window_onload_auto() {
    let body = r#"<script>
        window.onload = () => document.body.requestFullscreen();
    </script>"#;
    let issues = analyze_fullscreen(body);
    assert!(issues.contains(&FullscreenIssue::AutoFullscreen));
}

#[test]
fn severity_keyboard_lock_highest() {
    assert_eq!(fullscreen_severity(&FullscreenIssue::KeyboardLock), 7.0);
}

#[test]
fn severity_detected_lowest() {
    assert_eq!(fullscreen_severity(&FullscreenIssue::ApiDetected), 3.0);
}

#[test]
fn to_operations_creates_entries() {
    let issues = vec![FullscreenIssue::ApiDetected, FullscreenIssue::PointerLock];
    let mut seq = 0;
    let ops = fullscreen_to_operations(&issues, &mut seq);
    assert_eq!(ops.len(), 2);
    assert_eq!(seq, 2);
}

#[test]
fn display_variants() {
    assert_eq!(FullscreenIssue::ApiDetected.to_string(), "api_detected");
    assert_eq!(FullscreenIssue::NoUserActivation.to_string(), "no_user_activation");
    assert_eq!(FullscreenIssue::FakeUiOverlay.to_string(), "fake_ui_overlay");
    assert_eq!(FullscreenIssue::KeyboardLock.to_string(), "keyboard_lock");
    assert_eq!(FullscreenIssue::PointerLock.to_string(), "pointer_lock");
    assert_eq!(FullscreenIssue::AutoFullscreen.to_string(), "auto_fullscreen");
}

#[test]
fn empty_body_no_issues() {
    assert!(analyze_fullscreen("").is_empty());
}
