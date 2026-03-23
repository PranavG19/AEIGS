use crate::window_management_audit::*;

#[test]
fn no_window_mgmt_no_issues() {
    assert!(analyze_window_management("<html><body>hello</body></html>").is_empty());
}

#[test]
fn detects_api_get_screen_details() {
    let body = r#"<script>const details = await window.getScreenDetails();</script>"#;
    let issues = analyze_window_management(body);
    assert!(issues.contains(&WindowManagementIssue::ApiDetected));
}

#[test]
fn detects_api_permission() {
    let body = r#"<script>
        const perm = await navigator.permissions.query({name: "window-management"});
    </script>"#;
    let issues = analyze_window_management(body);
    assert!(issues.contains(&WindowManagementIssue::ApiDetected));
}

#[test]
fn detects_screen_enumeration() {
    let body = r#"<script>
        const details = await window.getScreenDetails();
        details.screens.forEach(s => console.log(s));
    </script>"#;
    let issues = analyze_window_management(body);
    assert!(issues.contains(&WindowManagementIssue::ScreenEnumeration));
}

#[test]
fn detects_cross_screen_popup() {
    let body = r#"<script>
        const details = await window.getScreenDetails();
        window.open("phishing.html", "_blank", "left=2000,top=0");
    </script>"#;
    let issues = analyze_window_management(body);
    assert!(issues.contains(&WindowManagementIssue::CrossScreenPopup));
}

#[test]
fn detects_screen_detail_exfiltration() {
    let body = r#"<script>
        const details = await window.getScreenDetails();
        fetch("/track?w=" + details.currentScreen.availWidth);
    </script>"#;
    let issues = analyze_window_management(body);
    assert!(issues.contains(&WindowManagementIssue::ScreenDetailExfiltration));
}

#[test]
fn no_exfil_without_fetch() {
    let body = r#"<script>
        const details = await window.getScreenDetails();
        console.log(details.currentScreen.availWidth);
    </script>"#;
    let issues = analyze_window_management(body);
    assert!(!issues.contains(&WindowManagementIssue::ScreenDetailExfiltration));
}

#[test]
fn detects_no_permission_check() {
    let body = r#"<script>const details = await window.getScreenDetails();</script>"#;
    let issues = analyze_window_management(body);
    assert!(issues.contains(&WindowManagementIssue::NoPermissionCheck));
}

#[test]
fn no_permission_issue_with_query() {
    let body = r#"<script>
        const perm = await navigator.permissions.query({name: "window-management"});
        if (perm.state === "granted") {
            const details = await window.getScreenDetails();
        }
    </script>"#;
    let issues = analyze_window_management(body);
    assert!(!issues.contains(&WindowManagementIssue::NoPermissionCheck));
}

#[test]
fn detects_fullscreen_on_external() {
    let body = r#"<script>
        const details = await window.getScreenDetails();
        const extScreen = details.screens[1];
        el.requestFullscreen({screen: extScreen});
    </script>"#;
    let issues = analyze_window_management(body);
    assert!(issues.contains(&WindowManagementIssue::FullscreenOnExternal));
}

#[test]
fn severity_exfiltration_highest() {
    assert_eq!(
        window_management_severity(&WindowManagementIssue::ScreenDetailExfiltration),
        6.5
    );
}

#[test]
fn severity_detected_lowest() {
    assert_eq!(
        window_management_severity(&WindowManagementIssue::ApiDetected),
        3.0
    );
}

#[test]
fn to_operations_creates_entries() {
    let issues = vec![
        WindowManagementIssue::ApiDetected,
        WindowManagementIssue::ScreenEnumeration,
    ];
    let mut seq = 0;
    let ops = window_management_to_operations(&issues, &mut seq);
    assert_eq!(ops.len(), 2);
    assert_eq!(seq, 2);
}

#[test]
fn display_variants() {
    assert_eq!(
        WindowManagementIssue::ApiDetected.to_string(),
        "api_detected"
    );
    assert_eq!(
        WindowManagementIssue::ScreenEnumeration.to_string(),
        "screen_enumeration"
    );
    assert_eq!(
        WindowManagementIssue::CrossScreenPopup.to_string(),
        "cross_screen_popup"
    );
    assert_eq!(
        WindowManagementIssue::ScreenDetailExfiltration.to_string(),
        "screen_detail_exfiltration"
    );
    assert_eq!(
        WindowManagementIssue::NoPermissionCheck.to_string(),
        "no_permission_check"
    );
    assert_eq!(
        WindowManagementIssue::FullscreenOnExternal.to_string(),
        "fullscreen_on_external"
    );
}

#[test]
fn empty_body_no_issues() {
    assert!(analyze_window_management("").is_empty());
}
