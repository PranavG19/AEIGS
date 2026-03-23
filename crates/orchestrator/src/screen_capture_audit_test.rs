use crate::screen_capture_audit::*;

#[test]
fn empty_body_no_issues() {
    let issues = analyze_screen_capture("");
    assert!(issues.is_empty());
}

#[test]
fn no_capture_api_no_issues() {
    let body = "<html><body>Hello</body></html>";
    let issues = analyze_screen_capture(body);
    assert!(issues.is_empty());
}

#[test]
fn detects_get_display_media() {
    let body = "navigator.mediaDevices.getDisplayMedia({video: true})";
    let issues = analyze_screen_capture(body);
    assert!(issues.contains(&ScreenCaptureIssue::GetDisplayMedia));
}

#[test]
fn detects_screen_capture_recording() {
    let body = r#"
        navigator.mediaDevices.getDisplayMedia({video: true}).then(stream => {
            var recorder = new MediaRecorder(stream);
        });
    "#;
    let issues = analyze_screen_capture(body);
    assert!(issues.contains(&ScreenCaptureIssue::ScreenCaptureRecording));
}

#[test]
fn detects_capture_exfiltration() {
    let body = r#"
        navigator.mediaDevices.getDisplayMedia({video: true}).then(stream => {
            fetch('/upload', {method:'POST', body: data});
        });
    "#;
    let issues = analyze_screen_capture(body);
    assert!(issues.contains(&ScreenCaptureIssue::CaptureDataExfiltration));
}

#[test]
fn detects_capture_without_ui() {
    let body = r#"
        <div style="display: none">
            <video id="screen"></video>
        </div>
        navigator.mediaDevices.getDisplayMedia({video: true});
    "#;
    let issues = analyze_screen_capture(body);
    assert!(issues.contains(&ScreenCaptureIssue::CaptureWithoutUi));
}

#[test]
fn detects_capture_stream_to_canvas() {
    let body = r#"
        navigator.mediaDevices.getDisplayMedia({video: true}).then(stream => {
            ctx.drawImage(video, 0, 0);
        });
    "#;
    let issues = analyze_screen_capture(body);
    assert!(issues.contains(&ScreenCaptureIssue::CaptureStreamToCanvas));
}

#[test]
fn detects_capture_stream_method() {
    let body = r#"
        navigator.mediaDevices.getDisplayMedia({video: true});
        canvas.captureStream(30);
    "#;
    let issues = analyze_screen_capture(body);
    assert!(issues.contains(&ScreenCaptureIssue::CaptureStreamToCanvas));
}

#[test]
fn detects_prefer_current_tab() {
    let body = r#"
        navigator.mediaDevices.getDisplayMedia({
            preferCurrentTab: true
        });
    "#;
    let issues = analyze_screen_capture(body);
    assert!(issues.contains(&ScreenCaptureIssue::PreferCurrentTab));
}

#[test]
fn severity_exfiltration_highest() {
    assert_eq!(
        screen_capture_severity(&ScreenCaptureIssue::CaptureDataExfiltration),
        8.0
    );
}

#[test]
fn severity_get_display_media_lowest() {
    assert_eq!(
        screen_capture_severity(&ScreenCaptureIssue::GetDisplayMedia),
        5.0
    );
}

#[test]
fn to_operations_creates_entries() {
    let issues = vec![
        ScreenCaptureIssue::GetDisplayMedia,
        ScreenCaptureIssue::ScreenCaptureRecording,
    ];
    let mut seq = 0;
    let ops = screen_capture_to_operations(&issues, &mut seq);
    assert_eq!(ops.len(), 2);
    assert_eq!(seq, 2);
}

#[test]
fn display_variants() {
    assert_eq!(
        ScreenCaptureIssue::GetDisplayMedia.to_string(),
        "get_display_media"
    );
    assert_eq!(
        ScreenCaptureIssue::ScreenCaptureRecording.to_string(),
        "screen_capture_recording"
    );
    assert_eq!(
        ScreenCaptureIssue::CaptureWithoutUi.to_string(),
        "capture_without_ui"
    );
    assert_eq!(
        ScreenCaptureIssue::PreferCurrentTab.to_string(),
        "prefer_current_tab"
    );
}

// ScreenCaptureSecurityIssue tests

#[test]
fn security_empty_body_no_issues() {
    let issues = analyze_screen_capture_security("");
    assert!(issues.is_empty());
}

#[test]
fn security_no_capture_api_no_issues() {
    let body = "<html><body>Hello</body></html>";
    let issues = analyze_screen_capture_security(body);
    assert!(issues.is_empty());
}

#[test]
fn security_guard_requires_getdisplaymedia_or_getscreendetails() {
    let body = "localStorage.setItem('test', 'data'); fetch('/api');";
    let issues = analyze_screen_capture_security(body);
    assert!(issues.is_empty());
}

#[test]
fn detects_capture_without_permission_policy() {
    let body = "navigator.mediaDevices.getDisplayMedia({video: true})";
    let issues = analyze_screen_capture_security(body);
    assert!(issues.contains(&ScreenCaptureSecurityIssue::CaptureWithoutPermissionPolicy));
}

#[test]
fn no_capture_without_permission_policy_when_policy_present() {
    let body = r#"
        // Permissions-Policy: display-capture=(self)
        navigator.mediaDevices.getDisplayMedia({video: true})
    "#;
    let issues = analyze_screen_capture_security(body);
    assert!(!issues.contains(&ScreenCaptureSecurityIssue::CaptureWithoutPermissionPolicy));
}

#[test]
fn no_capture_without_permission_policy_with_lowercase_header() {
    let body = r#"
        // permissions-policy: display-capture=(self)
        navigator.mediaDevices.getDisplayMedia({video: true})
    "#;
    let issues = analyze_screen_capture_security(body);
    assert!(!issues.contains(&ScreenCaptureSecurityIssue::CaptureWithoutPermissionPolicy));
}

#[test]
fn detects_silent_recording() {
    let body = r#"
        navigator.mediaDevices.getDisplayMedia({video: true}).then(stream => {
            const recorder = new MediaRecorder(stream);
            recorder.start();
        });
    "#;
    let issues = analyze_screen_capture_security(body);
    assert!(issues.contains(&ScreenCaptureSecurityIssue::SilentRecording));
}

#[test]
fn no_silent_recording_with_indicator() {
    let body = r#"
        navigator.mediaDevices.getDisplayMedia({video: true}).then(stream => {
            const recorder = new MediaRecorder(stream);
            showElement('recording-indicator');
        });
    "#;
    let issues = analyze_screen_capture_security(body);
    assert!(!issues.contains(&ScreenCaptureSecurityIssue::SilentRecording));
}

#[test]
fn no_silent_recording_with_rec_icon() {
    let body = r#"
        navigator.mediaDevices.getDisplayMedia({video: true}).then(stream => {
            const recorder = new MediaRecorder(stream);
            document.getElementById('rec-icon').style.display = 'block';
        });
    "#;
    let issues = analyze_screen_capture_security(body);
    assert!(!issues.contains(&ScreenCaptureSecurityIssue::SilentRecording));
}

#[test]
fn no_silent_recording_with_recording_badge() {
    let body = r#"
        navigator.mediaDevices.getDisplayMedia({video: true}).then(stream => {
            const recorder = new MediaRecorder(stream);
            addRecordingBadge('recording-badge');
        });
    "#;
    let issues = analyze_screen_capture_security(body);
    assert!(!issues.contains(&ScreenCaptureSecurityIssue::SilentRecording));
}

#[test]
fn detects_screenshot_exfiltration_toblob_fetch() {
    let body = r#"
        const stream = await navigator.mediaDevices.getDisplayMedia({video: true});
        canvas.toBlob(blob => {
            fetch('/upload', {method: 'POST', body: blob});
        });
    "#;
    let issues = analyze_screen_capture_security(body);
    assert!(issues.contains(&ScreenCaptureSecurityIssue::ScreenshotExfiltration));
}

#[test]
fn detects_screenshot_exfiltration_todataurl_xhr() {
    let body = r#"
        const stream = await navigator.mediaDevices.getDisplayMedia({video: true});
        const dataUrl = canvas.toDataURL('image/png');
        const xhr = new XMLHttpRequest();
        xhr.open('POST', '/save');
        xhr.send(dataUrl);
    "#;
    let issues = analyze_screen_capture_security(body);
    assert!(issues.contains(&ScreenCaptureSecurityIssue::ScreenshotExfiltration));
}

#[test]
fn detects_screenshot_exfiltration_canvas_sendbeacon() {
    let body = r#"
        const stream = await navigator.mediaDevices.getDisplayMedia({video: true});
        const canvas = document.createElement('canvas');
        const data = canvas.toDataURL();
        navigator.sendBeacon('/track', data);
    "#;
    let issues = analyze_screen_capture_security(body);
    assert!(issues.contains(&ScreenCaptureSecurityIssue::ScreenshotExfiltration));
}

#[test]
fn no_screenshot_exfiltration_without_network() {
    let body = r#"
        const blob = canvas.toBlob(blob => {
            console.log('Captured');
        });
    "#;
    let issues = analyze_screen_capture_security(body);
    assert!(!issues.contains(&ScreenCaptureSecurityIssue::ScreenshotExfiltration));
}

#[test]
fn detects_multi_monitor_capture() {
    let body = r#"
        window.getScreenDetails().then(screens => {
            screens.forEach(screen => console.log(screen.label));
        });
    "#;
    let issues = analyze_screen_capture_security(body);
    assert!(issues.contains(&ScreenCaptureSecurityIssue::MultiMonitorCapture));
}

#[test]
fn multi_monitor_capture_triggers_guard() {
    let body = "window.getScreenDetails().then(s => s);";
    let issues = analyze_screen_capture_security(body);
    assert!(!issues.is_empty()); // Guard allows getScreenDetails
}

#[test]
fn detects_audio_capture_combined_with_space() {
    let body = r#"
        navigator.mediaDevices.getDisplayMedia({
            video: true,
            audio: true
        });
    "#;
    let issues = analyze_screen_capture_security(body);
    assert!(issues.contains(&ScreenCaptureSecurityIssue::AudioCaptureCombined));
}

#[test]
fn detects_audio_capture_combined_no_space() {
    let body = r#"
        navigator.mediaDevices.getDisplayMedia({video:true,audio:true});
    "#;
    let issues = analyze_screen_capture_security(body);
    assert!(issues.contains(&ScreenCaptureSecurityIssue::AudioCaptureCombined));
}

#[test]
fn no_audio_capture_combined_without_audio() {
    let body = "navigator.mediaDevices.getDisplayMedia({video: true, audio: false});";
    let issues = analyze_screen_capture_security(body);
    assert!(!issues.contains(&ScreenCaptureSecurityIssue::AudioCaptureCombined));
}

#[test]
fn detects_continuous_capture_setinterval() {
    let body = r#"
        setInterval(() => {
            navigator.mediaDevices.getDisplayMedia({video: true});
        }, 5000);
    "#;
    let issues = analyze_screen_capture_security(body);
    assert!(issues.contains(&ScreenCaptureSecurityIssue::ContinuousCapture));
}

#[test]
fn detects_continuous_capture_while_loop() {
    let body = r#"
        while (true) {
            await navigator.mediaDevices.getDisplayMedia({video: true});
            await sleep(1000);
        }
    "#;
    let issues = analyze_screen_capture_security(body);
    assert!(issues.contains(&ScreenCaptureSecurityIssue::ContinuousCapture));
}

#[test]
fn detects_continuous_capture_for_loop_no_space() {
    let body = r#"
        for(let i=0; i<10; i++) {
            navigator.mediaDevices.getDisplayMedia({video: true});
        }
    "#;
    let issues = analyze_screen_capture_security(body);
    assert!(issues.contains(&ScreenCaptureSecurityIssue::ContinuousCapture));
}

#[test]
fn detects_continuous_capture_for_loop_with_space() {
    let body = r#"
        for (let i = 0; i < 10; i++) {
            navigator.mediaDevices.getDisplayMedia({video: true});
        }
    "#;
    let issues = analyze_screen_capture_security(body);
    assert!(issues.contains(&ScreenCaptureSecurityIssue::ContinuousCapture));
}

#[test]
fn detects_worker_based_capture_with_worker() {
    let body = r#"
        const worker = new Worker('capture-worker.js');
        worker.postMessage({action: 'startCapture'});
        navigator.mediaDevices.getDisplayMedia({video: true});
    "#;
    let issues = analyze_screen_capture_security(body);
    assert!(issues.contains(&ScreenCaptureSecurityIssue::WorkerBasedCapture));
}

#[test]
fn detects_worker_based_capture_getscreendetails_postmessage() {
    let body = r#"
        window.getScreenDetails().then(screens => {
            window.parent.postMessage(screens, '*');
        });
    "#;
    let issues = analyze_screen_capture_security(body);
    assert!(issues.contains(&ScreenCaptureSecurityIssue::WorkerBasedCapture));
}

#[test]
fn no_worker_based_capture_without_worker() {
    let body = "navigator.mediaDevices.getDisplayMedia({video: true});";
    let issues = analyze_screen_capture_security(body);
    assert!(!issues.contains(&ScreenCaptureSecurityIssue::WorkerBasedCapture));
}

#[test]
fn detects_capture_to_storage_localstorage() {
    let body = r#"
        navigator.mediaDevices.getDisplayMedia({video: true}).then(stream => {
            localStorage.setItem('captureStream', stream.id);
        });
    "#;
    let issues = analyze_screen_capture_security(body);
    assert!(issues.contains(&ScreenCaptureSecurityIssue::CaptureToStorage));
}

#[test]
fn detects_capture_to_storage_sessionstorage() {
    let body = r#"
        const stream = await navigator.mediaDevices.getDisplayMedia({video: true});
        canvas.toBlob(blob => {
            sessionStorage.setItem('screenshot', blob);
        });
    "#;
    let issues = analyze_screen_capture_security(body);
    assert!(issues.contains(&ScreenCaptureSecurityIssue::CaptureToStorage));
}

#[test]
fn detects_capture_to_storage_indexeddb_lowercase() {
    let body = r#"
        const stream = await navigator.mediaDevices.getDisplayMedia({video: true});
        const dataUrl = canvas.toDataURL();
        const request = indexedDB.open('captureDB', 1);
        request.onsuccess = e => e.target.result.add(dataUrl);
    "#;
    let issues = analyze_screen_capture_security(body);
    assert!(issues.contains(&ScreenCaptureSecurityIssue::CaptureToStorage));
}

#[test]
fn detects_capture_to_storage_indexeddb_uppercase() {
    let body = r#"
        navigator.mediaDevices.getDisplayMedia({video: true});
        IndexedDB.open('db');
    "#;
    let issues = analyze_screen_capture_security(body);
    assert!(issues.contains(&ScreenCaptureSecurityIssue::CaptureToStorage));
}

#[test]
fn no_capture_to_storage_without_storage_api() {
    let body = "navigator.mediaDevices.getDisplayMedia({video: true});";
    let issues = analyze_screen_capture_security(body);
    assert!(!issues.contains(&ScreenCaptureSecurityIssue::CaptureToStorage));
}

#[test]
fn detects_cross_origin_capture_share_getdisplaymedia() {
    let body = r#"
        navigator.mediaDevices.getDisplayMedia({video: true}).then(stream => {
            window.parent.postMessage({stream: stream.id}, '*');
        });
    "#;
    let issues = analyze_screen_capture_security(body);
    assert!(issues.contains(&ScreenCaptureSecurityIssue::CrossOriginCaptureShare));
}

#[test]
fn detects_cross_origin_capture_share_toblob() {
    let body = r#"
        const stream = await navigator.mediaDevices.getDisplayMedia({video: true});
        canvas.toBlob(blob => {
            window.postMessage(blob, 'https://example.com');
        });
    "#;
    let issues = analyze_screen_capture_security(body);
    assert!(issues.contains(&ScreenCaptureSecurityIssue::CrossOriginCaptureShare));
}

#[test]
fn detects_cross_origin_capture_share_todataurl() {
    let body = r#"
        const stream = await navigator.mediaDevices.getDisplayMedia({video: true});
        const data = canvas.toDataURL();
        iframe.contentWindow.postMessage(data, '*');
    "#;
    let issues = analyze_screen_capture_security(body);
    assert!(issues.contains(&ScreenCaptureSecurityIssue::CrossOriginCaptureShare));
}

#[test]
fn no_cross_origin_share_without_postmessage() {
    let body = r#"
        navigator.mediaDevices.getDisplayMedia({video: true}).then(stream => {
            console.log(stream);
        });
    "#;
    let issues = analyze_screen_capture_security(body);
    assert!(!issues.contains(&ScreenCaptureSecurityIssue::CrossOriginCaptureShare));
}

#[test]
fn detects_capture_without_user_gesture() {
    let body = r#"
        window.onload = function() {
            navigator.mediaDevices.getDisplayMedia({video: true});
        }
    "#;
    let issues = analyze_screen_capture_security(body);
    assert!(issues.contains(&ScreenCaptureSecurityIssue::CaptureWithoutUserGesture));
}

#[test]
fn no_capture_without_user_gesture_with_addeventlistener() {
    let body = r#"
        button.addEventListener('click', () => {
            navigator.mediaDevices.getDisplayMedia({video: true});
        });
    "#;
    let issues = analyze_screen_capture_security(body);
    assert!(!issues.contains(&ScreenCaptureSecurityIssue::CaptureWithoutUserGesture));
}

#[test]
fn no_capture_without_user_gesture_with_onclick() {
    let body = r#"
        <button onclick="navigator.mediaDevices.getDisplayMedia({video: true})">
            Share Screen
        </button>
    "#;
    let issues = analyze_screen_capture_security(body);
    assert!(!issues.contains(&ScreenCaptureSecurityIssue::CaptureWithoutUserGesture));
}

#[test]
fn no_capture_without_user_gesture_with_ontouchstart() {
    let body = r#"
        element.ontouchstart = () => {
            navigator.mediaDevices.getDisplayMedia({video: true});
        };
    "#;
    let issues = analyze_screen_capture_security(body);
    assert!(!issues.contains(&ScreenCaptureSecurityIssue::CaptureWithoutUserGesture));
}

#[test]
fn no_capture_without_user_gesture_with_onclick_react() {
    let body = r#"
        <Button onClick={() => navigator.mediaDevices.getDisplayMedia({video: true})}>
            Start Capture
        </Button>
    "#;
    let issues = analyze_screen_capture_security(body);
    assert!(!issues.contains(&ScreenCaptureSecurityIssue::CaptureWithoutUserGesture));
}

#[test]
fn security_display_variants() {
    assert_eq!(
        ScreenCaptureSecurityIssue::CaptureWithoutPermissionPolicy.to_string(),
        "capture_without_permission_policy"
    );
    assert_eq!(
        ScreenCaptureSecurityIssue::SilentRecording.to_string(),
        "silent_recording"
    );
    assert_eq!(
        ScreenCaptureSecurityIssue::ScreenshotExfiltration.to_string(),
        "screenshot_exfiltration"
    );
    assert_eq!(
        ScreenCaptureSecurityIssue::MultiMonitorCapture.to_string(),
        "multi_monitor_capture"
    );
    assert_eq!(
        ScreenCaptureSecurityIssue::AudioCaptureCombined.to_string(),
        "audio_capture_combined"
    );
    assert_eq!(
        ScreenCaptureSecurityIssue::ContinuousCapture.to_string(),
        "continuous_capture"
    );
    assert_eq!(
        ScreenCaptureSecurityIssue::WorkerBasedCapture.to_string(),
        "worker_based_capture"
    );
    assert_eq!(
        ScreenCaptureSecurityIssue::CaptureToStorage.to_string(),
        "capture_to_storage"
    );
    assert_eq!(
        ScreenCaptureSecurityIssue::CrossOriginCaptureShare.to_string(),
        "cross_origin_capture_share"
    );
    assert_eq!(
        ScreenCaptureSecurityIssue::CaptureWithoutUserGesture.to_string(),
        "capture_without_user_gesture"
    );
}

#[test]
fn security_severity_screenshot_exfiltration_highest() {
    assert_eq!(
        screen_capture_security_severity(&ScreenCaptureSecurityIssue::ScreenshotExfiltration),
        9.0
    );
}

#[test]
fn security_severity_silent_recording_very_high() {
    assert_eq!(
        screen_capture_security_severity(&ScreenCaptureSecurityIssue::SilentRecording),
        8.5
    );
}

#[test]
fn security_severity_multi_monitor_high() {
    assert_eq!(
        screen_capture_security_severity(&ScreenCaptureSecurityIssue::MultiMonitorCapture),
        8.0
    );
}

#[test]
fn security_severity_cross_origin_share() {
    assert_eq!(
        screen_capture_security_severity(&ScreenCaptureSecurityIssue::CrossOriginCaptureShare),
        7.5
    );
}

#[test]
fn security_severity_capture_to_storage() {
    assert_eq!(
        screen_capture_security_severity(&ScreenCaptureSecurityIssue::CaptureToStorage),
        7.0
    );
}

#[test]
fn security_severity_audio_combined() {
    assert_eq!(
        screen_capture_security_severity(&ScreenCaptureSecurityIssue::AudioCaptureCombined),
        6.5
    );
}

#[test]
fn security_severity_worker_based() {
    assert_eq!(
        screen_capture_security_severity(&ScreenCaptureSecurityIssue::WorkerBasedCapture),
        6.0
    );
}

#[test]
fn security_severity_continuous_capture() {
    assert_eq!(
        screen_capture_security_severity(&ScreenCaptureSecurityIssue::ContinuousCapture),
        5.5
    );
}

#[test]
fn security_severity_without_user_gesture() {
    assert_eq!(
        screen_capture_security_severity(&ScreenCaptureSecurityIssue::CaptureWithoutUserGesture),
        5.0
    );
}

#[test]
fn security_severity_without_permission_policy_lowest() {
    assert_eq!(
        screen_capture_security_severity(
            &ScreenCaptureSecurityIssue::CaptureWithoutPermissionPolicy
        ),
        4.5
    );
}

#[test]
fn security_to_operations_creates_entries() {
    let issues = vec![
        ScreenCaptureSecurityIssue::ScreenshotExfiltration,
        ScreenCaptureSecurityIssue::SilentRecording,
        ScreenCaptureSecurityIssue::MultiMonitorCapture,
    ];
    let mut seq = 0;
    let ops = screen_capture_security_to_operations(&issues, &mut seq);
    assert_eq!(ops.len(), 3);
    assert_eq!(seq, 3);
}

#[test]
fn security_to_operations_empty_input() {
    let issues = vec![];
    let mut seq = 42;
    let ops = screen_capture_security_to_operations(&issues, &mut seq);
    assert!(ops.is_empty());
    assert_eq!(seq, 42);
}

#[test]
fn security_complex_scenario_multiple_issues() {
    let body = r#"
        const worker = new Worker('capture.js');
        setInterval(() => {
            navigator.mediaDevices.getDisplayMedia({
                video: true,
                audio: true
            }).then(stream => {
                const recorder = new MediaRecorder(stream);
                recorder.ondataavailable = e => {
                    const blob = e.data;
                    canvas.toBlob(screenshot => {
                        fetch('/upload', {method: 'POST', body: screenshot});
                        localStorage.setItem('lastCapture', screenshot);
                        window.postMessage(blob, '*');
                    });
                };
            });
        }, 10000);
    "#;
    let issues = analyze_screen_capture_security(body);
    assert!(issues.contains(&ScreenCaptureSecurityIssue::CaptureWithoutPermissionPolicy));
    assert!(issues.contains(&ScreenCaptureSecurityIssue::SilentRecording));
    assert!(issues.contains(&ScreenCaptureSecurityIssue::ScreenshotExfiltration));
    assert!(issues.contains(&ScreenCaptureSecurityIssue::AudioCaptureCombined));
    assert!(issues.contains(&ScreenCaptureSecurityIssue::ContinuousCapture));
    assert!(issues.contains(&ScreenCaptureSecurityIssue::WorkerBasedCapture));
    assert!(issues.contains(&ScreenCaptureSecurityIssue::CaptureToStorage));
    assert!(issues.contains(&ScreenCaptureSecurityIssue::CrossOriginCaptureShare));
    assert!(issues.len() >= 8);
}

#[test]
fn security_edge_case_whitespace_variations() {
    let body = "audio:true";
    let issues = analyze_screen_capture_security(body);
    assert!(issues.is_empty()); // Guard prevents without getDisplayMedia
}

#[test]
fn security_edge_case_mixed_case_apis() {
    let body = r#"
        navigator.mediaDevices.getDisplayMedia({video: true});
        LOCALSTORAGE.setItem('test', 'data');
    "#;
    let issues = analyze_screen_capture_security(body);
    assert!(!issues.contains(&ScreenCaptureSecurityIssue::CaptureToStorage)); // Case-sensitive
}

#[test]
fn security_minimal_valid_code() {
    let body = "getDisplayMedia";
    let issues = analyze_screen_capture_security(body);
    assert!(!issues.is_empty()); // Should detect at least CaptureWithoutPermissionPolicy
}
