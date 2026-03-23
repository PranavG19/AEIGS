use crate::storage_access_audit::*;

#[test]
fn no_api_no_issues() {
    assert!(analyze_storage_access("<html><body>Hello</body></html>").is_empty());
}

#[test]
fn detects_api_with_request_storage_access() {
    let body = r#"<script>document.requestStorageAccess()</script>"#;
    let issues = analyze_storage_access(body);
    assert!(issues.contains(&StorageAccessIssue::ApiDetected));
}

#[test]
fn detects_api_with_has_storage_access() {
    let body = r#"<script>document.hasStorageAccess()</script>"#;
    let issues = analyze_storage_access(body);
    assert!(issues.contains(&StorageAccessIssue::ApiDetected));
}

#[test]
fn detects_third_party_cookie_access_in_iframe() {
    let body = r#"
        <iframe src="https://third-party.com">
            <script>
                document.requestStorageAccess().then(() => {
                    console.log("Access granted");
                });
            </script>
        </iframe>
    "#;
    let issues = analyze_storage_access(body);
    assert!(issues.contains(&StorageAccessIssue::ThirdPartyCookieAccess));
}

#[test]
fn detects_cross_site_tracking() {
    let body = r#"
        <script>
            document.requestStorageAccess().then(() => {
                analytics.track("user_action");
            });
        </script>
    "#;
    let issues = analyze_storage_access(body);
    assert!(issues.contains(&StorageAccessIssue::CrossSiteTracking));
}

#[test]
fn detects_cross_site_tracking_with_pixel() {
    let body = r#"
        <script>
            document.requestStorageAccess().then(() => {
                loadTrackingpixel();
            });
        </script>
    "#;
    let issues = analyze_storage_access(body);
    assert!(issues.contains(&StorageAccessIssue::CrossSiteTracking));
}

#[test]
fn detects_cross_site_tracking_with_facebook() {
    let body = r#"
        <script>
            document.requestStorageAccess().then(() => {
                fbq('track', 'PageView');
            });
        </script>
    "#;
    let issues = analyze_storage_access(body);
    assert!(issues.contains(&StorageAccessIssue::CrossSiteTracking));
}

#[test]
fn detects_missing_permission_check() {
    let body = r#"
        <script>
            document.requestStorageAccess().then(() => {
                loadCookies();
            });
        </script>
    "#;
    let issues = analyze_storage_access(body);
    assert!(issues.contains(&StorageAccessIssue::MissingPermissionCheck));
}

#[test]
fn no_missing_permission_with_check() {
    let body = r#"
        <script>
            navigator.permissions.query({name: 'storage-access'}).then(permission => {
                if (permission.state === 'granted') {
                    document.requestStorageAccess();
                }
            });
        </script>
    "#;
    let issues = analyze_storage_access(body);
    assert!(!issues.contains(&StorageAccessIssue::MissingPermissionCheck));
}

#[test]
fn detects_sensitive_data_access_with_password() {
    let body = r#"
        <script>
            document.requestStorageAccess().then(() => {
                const password = localStorage.getItem('password');
            });
        </script>
    "#;
    let issues = analyze_storage_access(body);
    assert!(issues.contains(&StorageAccessIssue::SensitiveDataAccess));
}

#[test]
fn detects_sensitive_data_access_with_token() {
    let body = r#"
        <script>
            document.requestStorageAccess().then(() => {
                const token = sessionStorage.getItem('auth_token');
            });
        </script>
    "#;
    let issues = analyze_storage_access(body);
    assert!(issues.contains(&StorageAccessIssue::SensitiveDataAccess));
}

#[test]
fn detects_sensitive_data_access_with_api_key() {
    let body = r#"
        <script>
            document.requestStorageAccess().then(() => {
                const key = localStorage.getItem('apiKey');
            });
        </script>
    "#;
    let issues = analyze_storage_access(body);
    assert!(issues.contains(&StorageAccessIssue::SensitiveDataAccess));
}

#[test]
fn no_sensitive_data_without_storage_access() {
    let body = r#"
        <script>
            document.requestStorageAccess().then(() => {
                const password = "hardcoded";
            });
        </script>
    "#;
    let issues = analyze_storage_access(body);
    assert!(!issues.contains(&StorageAccessIssue::SensitiveDataAccess));
}

#[test]
fn detects_no_user_gesture_in_iframe() {
    let body = r#"
        <iframe src="https://third-party.com">
            <script>
                document.requestStorageAccess();
            </script>
        </iframe>
    "#;
    let issues = analyze_storage_access(body);
    assert!(issues.contains(&StorageAccessIssue::NoUserGesture));
}

#[test]
fn no_user_gesture_issue_with_click_handler() {
    let body = r#"
        <iframe src="https://third-party.com">
            <script>
                button.addEventListener("click", () => {
                    document.requestStorageAccess();
                });
            </script>
        </iframe>
    "#;
    let issues = analyze_storage_access(body);
    assert!(!issues.contains(&StorageAccessIssue::NoUserGesture));
}

#[test]
fn no_user_gesture_issue_with_onclick() {
    let body = r#"
        <iframe src="https://third-party.com">
            <script>
                button.onclick = () => {
                    document.requestStorageAccess();
                };
            </script>
        </iframe>
    "#;
    let issues = analyze_storage_access(body);
    assert!(!issues.contains(&StorageAccessIssue::NoUserGesture));
}

#[test]
fn detects_iframe_without_sandbox() {
    let body = r#"
        <iframe src="https://third-party.com">
            <script>
                document.requestStorageAccess();
            </script>
        </iframe>
    "#;
    let issues = analyze_storage_access(body);
    assert!(issues.contains(&StorageAccessIssue::IframeWithoutSandbox));
}

#[test]
fn no_iframe_issue_with_proper_sandbox() {
    let body = r#"
        <iframe src="https://third-party.com" sandbox="allow-scripts allow-storage-access-by-user-activation">
            <script>
                document.requestStorageAccess();
            </script>
        </iframe>
    "#;
    let issues = analyze_storage_access(body);
    assert!(!issues.contains(&StorageAccessIssue::IframeWithoutSandbox));
}

#[test]
fn severity_sensitive_data_highest() {
    assert_eq!(
        storage_access_severity(&StorageAccessIssue::SensitiveDataAccess),
        7.5
    );
}

#[test]
fn severity_api_detected_lowest() {
    assert_eq!(
        storage_access_severity(&StorageAccessIssue::ApiDetected),
        3.0
    );
}

#[test]
fn to_operations_creates_entries() {
    let issues = vec![
        StorageAccessIssue::ApiDetected,
        StorageAccessIssue::ThirdPartyCookieAccess,
        StorageAccessIssue::CrossSiteTracking,
    ];
    let mut seq = 0u64;
    let ops = storage_access_to_operations(&issues, &mut seq);
    assert_eq!(ops.len(), 3);
    assert_eq!(seq, 3);
}

#[test]
fn display_api_detected() {
    assert_eq!(StorageAccessIssue::ApiDetected.to_string(), "api_detected");
}

#[test]
fn display_third_party_cookie_access() {
    assert_eq!(
        StorageAccessIssue::ThirdPartyCookieAccess.to_string(),
        "third_party_cookie_access"
    );
}

#[test]
fn display_cross_site_tracking() {
    assert_eq!(
        StorageAccessIssue::CrossSiteTracking.to_string(),
        "cross_site_tracking"
    );
}

#[test]
fn display_missing_permission_check() {
    assert_eq!(
        StorageAccessIssue::MissingPermissionCheck.to_string(),
        "missing_permission_check"
    );
}

#[test]
fn display_sensitive_data_access() {
    assert_eq!(
        StorageAccessIssue::SensitiveDataAccess.to_string(),
        "sensitive_data_access"
    );
}
