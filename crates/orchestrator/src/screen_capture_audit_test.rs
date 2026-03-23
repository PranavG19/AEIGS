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
