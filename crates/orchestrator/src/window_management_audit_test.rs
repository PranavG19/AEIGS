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

#[test]
fn security_no_issues_on_simple_html() {
    let body = "<html><body>hello world</body></html>";
    assert!(analyze_window_management_security(body).is_empty());
}

#[test]
fn security_detects_screen_enumeration() {
    let body = r#"<script>
        const details = await window.getScreenDetails();
        console.log(details.screens.length);
    </script>"#;
    let issues = analyze_window_management_security(body);
    assert!(issues.contains(&WindowManagementSecurityIssue::ScreenEnumeration));
}

#[test]
fn security_no_screen_enum_without_length() {
    let body = r#"<script>
        const details = await window.getScreenDetails();
        console.log(details.screens);
    </script>"#;
    let issues = analyze_window_management_security(body);
    assert!(!issues.contains(&WindowManagementSecurityIssue::ScreenEnumeration));
}

#[test]
fn security_detects_window_position_tracking() {
    let body = r#"<script>
        setInterval(() => {
            console.log(window.screenX, window.screenY);
        }, 100);
    </script>"#;
    let issues = analyze_window_management_security(body);
    assert!(issues.contains(&WindowManagementSecurityIssue::WindowPositionTracking));
}

#[test]
fn security_detects_window_position_tracking_with_raf() {
    let body = r#"<script>
        function track() {
            console.log(window.screenX, window.screenY);
            requestAnimationFrame(track);
        }
        track();
    </script>"#;
    let issues = analyze_window_management_security(body);
    assert!(issues.contains(&WindowManagementSecurityIssue::WindowPositionTracking));
}

#[test]
fn security_no_position_tracking_without_interval() {
    let body = r#"<script>
        console.log(window.screenX, window.screenY);
    </script>"#;
    let issues = analyze_window_management_security(body);
    assert!(!issues.contains(&WindowManagementSecurityIssue::WindowPositionTracking));
}

#[test]
fn security_detects_multi_screen_fingerprinting() {
    let body = r#"<script>
        const details = await window.getScreenDetails();
        const fingerprint = details.screens.map(s => s.devicePixelRatio).join(',');
        localStorage.setItem('screen_fp', fingerprint);
    </script>"#;
    let issues = analyze_window_management_security(body);
    assert!(issues.contains(&WindowManagementSecurityIssue::MultiScreenFingerprinting));
}

#[test]
fn security_detects_fingerprinting_with_session_storage() {
    let body = r#"<script>
        const details = await window.getScreenDetails();
        const fp = details.screens.map(s => s.devicePixelRatio);
        sessionStorage.setItem('fp', JSON.stringify(fp));
    </script>"#;
    let issues = analyze_window_management_security(body);
    assert!(issues.contains(&WindowManagementSecurityIssue::MultiScreenFingerprinting));
}

#[test]
fn security_detects_fingerprinting_with_indexeddb() {
    let body = r#"<script>
        const details = await window.getScreenDetails();
        const fp = details.screens.map(s => s.devicePixelRatio);
        const db = await indexedDB.open('fp');
        db.put(fp);
    </script>"#;
    let issues = analyze_window_management_security(body);
    assert!(issues.contains(&WindowManagementSecurityIssue::MultiScreenFingerprinting));
}

#[test]
fn security_no_fingerprinting_without_storage() {
    let body = r#"<script>
        const details = await window.getScreenDetails();
        console.log(details.screens.map(s => s.devicePixelRatio));
    </script>"#;
    let issues = analyze_window_management_security(body);
    assert!(!issues.contains(&WindowManagementSecurityIssue::MultiScreenFingerprinting));
}

#[test]
fn security_detects_window_placement_abuse() {
    let body = r#"<script>
        const details = await window.getScreenDetails();
        const ext = details.screens[1];
        window.open('ad.html', '_blank', 'left=3000,top=0');
    </script>"#;
    let issues = analyze_window_management_security(body);
    assert!(issues.contains(&WindowManagementSecurityIssue::WindowPlacementAbuse));
}

#[test]
fn security_detects_placement_abuse_with_top() {
    let body = r#"<script>
        const details = await window.getScreenDetails();
        const ext = details.screens[0];
        window.open('popup.html', '_blank', 'top=1000');
    </script>"#;
    let issues = analyze_window_management_security(body);
    assert!(issues.contains(&WindowManagementSecurityIssue::WindowPlacementAbuse));
}

#[test]
fn security_no_placement_abuse_without_coords() {
    let body = r#"<script>
        const details = await window.getScreenDetails();
        window.open('popup.html', '_blank');
    </script>"#;
    let issues = analyze_window_management_security(body);
    assert!(!issues.contains(&WindowManagementSecurityIssue::WindowPlacementAbuse));
}

#[test]
fn security_detects_fullscreen_on_all_screens() {
    let body = r#"<script>
        const details = await window.getScreenDetails();
        details.screens.forEach(screen => {
            el.requestFullscreen({screen: screen});
        });
    </script>"#;
    let issues = analyze_window_management_security(body);
    assert!(issues.contains(&WindowManagementSecurityIssue::FullscreenOnAllScreens));
}

#[test]
fn security_detects_fullscreen_with_for_loop() {
    let body = r#"<script>
        const details = await window.getScreenDetails();
        for (let i = 0; i < details.screens.length; i++) {
            el.requestFullscreen({screen: details.screens[i]});
        }
    </script>"#;
    let issues = analyze_window_management_security(body);
    assert!(issues.contains(&WindowManagementSecurityIssue::FullscreenOnAllScreens));
}

#[test]
fn security_no_fullscreen_without_loop() {
    let body = r#"<script>
        const details = await window.getScreenDetails();
        el.requestFullscreen({screen: details.screens[0]});
    </script>"#;
    let issues = analyze_window_management_security(body);
    assert!(!issues.contains(&WindowManagementSecurityIssue::FullscreenOnAllScreens));
}

#[test]
fn security_detects_window_cross_origin_positioning() {
    let body = r#"<script>
        const pos = {x: window.screenX, y: window.screenY};
        iframe.contentWindow.postMessage(pos, '*');
    </script>"#;
    let issues = analyze_window_management_security(body);
    assert!(issues.contains(&WindowManagementSecurityIssue::WindowCrossOriginPositioning));
}

#[test]
fn security_detects_cross_origin_with_screeny() {
    let body = r#"<script>
        window.parent.postMessage({screenY: window.screenY}, '*');
    </script>"#;
    let issues = analyze_window_management_security(body);
    assert!(issues.contains(&WindowManagementSecurityIssue::WindowCrossOriginPositioning));
}

#[test]
fn security_no_cross_origin_without_postmessage() {
    let body = r#"<script>
        console.log(window.screenX, window.screenY);
    </script>"#;
    let issues = analyze_window_management_security(body);
    assert!(!issues.contains(&WindowManagementSecurityIssue::WindowCrossOriginPositioning));
}

#[test]
fn security_detects_screen_details_surveillance() {
    let body = r#"<script>
        const details = await window.getScreenDetails();
        const profile = {
            width: details.currentScreen.availWidth,
            height: details.currentScreen.availHeight,
            color: details.currentScreen.colorDepth,
            orientation: details.currentScreen.orientation,
            primary: details.currentScreen.isPrimary,
            internal: details.currentScreen.isInternal
        };
    </script>"#;
    let issues = analyze_window_management_security(body);
    assert!(issues.contains(&WindowManagementSecurityIssue::ScreenDetailsSurveillance));
}

#[test]
fn security_surveillance_requires_three_indicators() {
    let body = r#"<script>
        const details = await window.getScreenDetails();
        console.log(details.currentScreen.availWidth);
        console.log(details.currentScreen.availHeight);
    </script>"#;
    let issues = analyze_window_management_security(body);
    assert!(!issues.contains(&WindowManagementSecurityIssue::ScreenDetailsSurveillance));
}

#[test]
fn security_detects_surveillance_with_three_exact() {
    let body = r#"<script>
        const details = await window.getScreenDetails();
        const w = details.currentScreen.availWidth;
        const h = details.currentScreen.availHeight;
        const c = details.currentScreen.colorDepth;
    </script>"#;
    let issues = analyze_window_management_security(body);
    assert!(issues.contains(&WindowManagementSecurityIssue::ScreenDetailsSurveillance));
}

#[test]
fn security_detects_window_in_background() {
    let body = r#"<script>
        document.addEventListener('visibilitychange', () => {
            if (document.hidden) {
                window.moveTo(-10000, -10000);
            }
        });
    </script>"#;
    let issues = analyze_window_management_security(body);
    assert!(issues.contains(&WindowManagementSecurityIssue::WindowInBackground));
}

#[test]
fn security_detects_background_with_moveby() {
    let body = r#"<script>
        if (document.visibilityState === 'hidden') {
            window.moveBy(5000, 5000);
        }
    </script>"#;
    let issues = analyze_window_management_security(body);
    assert!(issues.contains(&WindowManagementSecurityIssue::WindowInBackground));
}

#[test]
fn security_no_background_without_positioning() {
    let body = r#"<script>
        document.addEventListener('visibilitychange', () => {
            console.log('hidden:', document.hidden);
        });
    </script>"#;
    let issues = analyze_window_management_security(body);
    assert!(!issues.contains(&WindowManagementSecurityIssue::WindowInBackground));
}

#[test]
fn security_detects_window_resize_tracking() {
    let body = r#"<script>
        window.addEventListener('resize', () => {
            fetch('/track', {
                method: 'POST',
                body: JSON.stringify({w: window.innerWidth, h: window.innerHeight})
            });
        });
    </script>"#;
    let issues = analyze_window_management_security(body);
    assert!(issues.contains(&WindowManagementSecurityIssue::WindowResizeTracking));
}

#[test]
fn security_detects_resize_tracking_with_beacon() {
    let body = r#"<script>
        window.addEventListener('resize', () => {
            navigator.sendBeacon('/track', JSON.stringify({w: window.innerWidth}));
        });
    </script>"#;
    let issues = analyze_window_management_security(body);
    assert!(issues.contains(&WindowManagementSecurityIssue::WindowResizeTracking));
}

#[test]
fn security_no_resize_tracking_without_exfil() {
    let body = r#"<script>
        window.addEventListener('resize', () => {
            console.log('resized');
        });
    </script>"#;
    let issues = analyze_window_management_security(body);
    assert!(!issues.contains(&WindowManagementSecurityIssue::WindowResizeTracking));
}

#[test]
fn security_detects_screen_label_exposure() {
    let body = r#"<script>
        const details = await window.getScreenDetails();
        const labels = details.screens.map(s => s.label);
        fetch('/collect', {
            method: 'POST',
            body: JSON.stringify(labels)
        });
    </script>"#;
    let issues = analyze_window_management_security(body);
    assert!(issues.contains(&WindowManagementSecurityIssue::ScreenLabelExposure));
}

#[test]
fn security_detects_label_exposure_with_xhr() {
    let body = r#"<script>
        const details = await window.getScreenDetails();
        const xhr = new XMLHttpRequest();
        xhr.open('POST', '/track');
        xhr.send(JSON.stringify(details.screens.map(s => s.label)));
    </script>"#;
    let issues = analyze_window_management_security(body);
    assert!(issues.contains(&WindowManagementSecurityIssue::ScreenLabelExposure));
}

#[test]
fn security_no_label_exposure_without_exfil() {
    let body = r#"<script>
        const details = await window.getScreenDetails();
        console.log(details.screens.map(s => s.label));
    </script>"#;
    let issues = analyze_window_management_security(body);
    assert!(!issues.contains(&WindowManagementSecurityIssue::ScreenLabelExposure));
}

#[test]
fn security_severity_surveillance_highest() {
    assert_eq!(
        window_management_security_severity(
            &WindowManagementSecurityIssue::ScreenDetailsSurveillance
        ),
        7.5
    );
}

#[test]
fn security_severity_fingerprinting_high() {
    assert_eq!(
        window_management_security_severity(
            &WindowManagementSecurityIssue::MultiScreenFingerprinting
        ),
        7.0
    );
}

#[test]
fn security_severity_enumeration_lowest() {
    assert_eq!(
        window_management_security_severity(&WindowManagementSecurityIssue::ScreenEnumeration),
        4.5
    );
}

#[test]
fn security_to_operations_creates_entries() {
    let issues = vec![
        WindowManagementSecurityIssue::ScreenEnumeration,
        WindowManagementSecurityIssue::WindowPositionTracking,
        WindowManagementSecurityIssue::MultiScreenFingerprinting,
    ];
    let mut seq = 0;
    let ops = window_management_security_to_operations(&issues, &mut seq);
    assert_eq!(ops.len(), 3);
    assert_eq!(seq, 3);
}

#[test]
fn security_display_screen_enumeration() {
    assert_eq!(
        WindowManagementSecurityIssue::ScreenEnumeration.to_string(),
        "screen_enumeration"
    );
}

#[test]
fn security_display_window_position_tracking() {
    assert_eq!(
        WindowManagementSecurityIssue::WindowPositionTracking.to_string(),
        "window_position_tracking"
    );
}

#[test]
fn security_display_multi_screen_fingerprinting() {
    assert_eq!(
        WindowManagementSecurityIssue::MultiScreenFingerprinting.to_string(),
        "multi_screen_fingerprinting"
    );
}

#[test]
fn security_display_window_placement_abuse() {
    assert_eq!(
        WindowManagementSecurityIssue::WindowPlacementAbuse.to_string(),
        "window_placement_abuse"
    );
}

#[test]
fn security_display_fullscreen_on_all_screens() {
    assert_eq!(
        WindowManagementSecurityIssue::FullscreenOnAllScreens.to_string(),
        "fullscreen_on_all_screens"
    );
}

#[test]
fn security_display_window_cross_origin_positioning() {
    assert_eq!(
        WindowManagementSecurityIssue::WindowCrossOriginPositioning.to_string(),
        "window_cross_origin_positioning"
    );
}

#[test]
fn security_display_screen_details_surveillance() {
    assert_eq!(
        WindowManagementSecurityIssue::ScreenDetailsSurveillance.to_string(),
        "screen_details_surveillance"
    );
}

#[test]
fn security_display_window_in_background() {
    assert_eq!(
        WindowManagementSecurityIssue::WindowInBackground.to_string(),
        "window_in_background"
    );
}

#[test]
fn security_display_window_resize_tracking() {
    assert_eq!(
        WindowManagementSecurityIssue::WindowResizeTracking.to_string(),
        "window_resize_tracking"
    );
}

#[test]
fn security_display_screen_label_exposure() {
    assert_eq!(
        WindowManagementSecurityIssue::ScreenLabelExposure.to_string(),
        "screen_label_exposure"
    );
}

#[test]
fn security_empty_body_no_issues() {
    assert!(analyze_window_management_security("").is_empty());
}
