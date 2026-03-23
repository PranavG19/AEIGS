use crate::storage_access_audit::*;

#[test]
fn no_api_no_issues() {
    assert!(analyze_storage_access("<html></html>").is_empty());
}

#[test]
fn detects_has_storage_access() {
    let body = r#"<script>document.hasStorageAccess().then(has => console.log(has))</script>"#;
    let issues = analyze_storage_access(body);
    assert!(issues.contains(&StorageAccessIssue::HasStorageAccess));
}

#[test]
fn detects_request_storage_access() {
    let body = r#"<script>document.requestStorageAccess().then(() => loadCookies())</script>"#;
    let issues = analyze_storage_access(body);
    assert!(issues.contains(&StorageAccessIssue::RequestStorageAccess));
}

#[test]
fn detects_request_storage_access_for() {
    let body = r#"<script>document.requestStorageAccessFor("https://third.party")</script>"#;
    let issues = analyze_storage_access(body);
    assert!(issues.contains(&StorageAccessIssue::RequestStorageAccessFor));
}

#[test]
fn detects_no_user_gesture() {
    let body = r#"<script>document.requestStorageAccess().then(() => {})</script>"#;
    let issues = analyze_storage_access(body);
    assert!(issues.contains(&StorageAccessIssue::NoUserGesture));
}

#[test]
fn no_gesture_issue_with_click() {
    let body = r#"<script>
        button.addEventListener("click", () => {
            document.requestStorageAccess();
        });
    </script>"#;
    let issues = analyze_storage_access(body);
    assert!(!issues.contains(&StorageAccessIssue::NoUserGesture));
}

#[test]
fn detects_iframe_context() {
    let body = r#"<script>
        const iframe = document.querySelector("iframe");
        document.requestStorageAccess();
    </script>"#;
    let issues = analyze_storage_access(body);
    assert!(issues.contains(&StorageAccessIssue::IframeContext));
}

#[test]
fn detects_auto_grant() {
    let body = r#"<script>document.requestStorageAccess().then(() => loadData())</script>"#;
    let issues = analyze_storage_access(body);
    assert!(issues.contains(&StorageAccessIssue::AutoGrant));
}

#[test]
fn no_auto_grant_with_catch() {
    let body = r#"<script>
        document.requestStorageAccess()
            .then(() => loadData())
            .catch(err => handleDenied(err));
    </script>"#;
    let issues = analyze_storage_access(body);
    assert!(!issues.contains(&StorageAccessIssue::AutoGrant));
}

#[test]
fn severity_access_for_highest() {
    assert_eq!(storage_access_severity(&StorageAccessIssue::RequestStorageAccessFor), 6.0);
}

#[test]
fn severity_has_lowest() {
    assert_eq!(storage_access_severity(&StorageAccessIssue::HasStorageAccess), 3.0);
}

#[test]
fn to_operations_creates_entries() {
    let issues = vec![
        StorageAccessIssue::HasStorageAccess,
        StorageAccessIssue::RequestStorageAccess,
    ];
    let mut seq = 0;
    let ops = storage_access_to_operations(&issues, &mut seq);
    assert_eq!(ops.len(), 2);
    assert_eq!(seq, 2);
}

#[test]
fn display_variants() {
    assert_eq!(StorageAccessIssue::HasStorageAccess.to_string(), "has_storage_access");
    assert_eq!(StorageAccessIssue::RequestStorageAccess.to_string(), "request_storage_access");
    assert_eq!(StorageAccessIssue::RequestStorageAccessFor.to_string(), "request_storage_access_for");
    assert_eq!(StorageAccessIssue::NoUserGesture.to_string(), "no_user_gesture");
    assert_eq!(StorageAccessIssue::IframeContext.to_string(), "iframe_context");
    assert_eq!(StorageAccessIssue::AutoGrant.to_string(), "auto_grant");
}

#[test]
fn empty_body_no_issues() {
    assert!(analyze_storage_access("").is_empty());
}
