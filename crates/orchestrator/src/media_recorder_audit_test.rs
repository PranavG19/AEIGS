use crate::media_recorder_audit::*;

#[test]
fn empty_body() {
    let issues = analyze_media_recorder("");
    assert!(issues.is_empty());
}

#[test]
fn no_api() {
    let body = "var x = document.createElement('video');";
    let issues = analyze_media_recorder(body);
    assert!(issues.is_empty());
}

#[test]
fn detects_media_recorder() {
    let body = "var rec = new MediaRecorder(stream);";
    let issues = analyze_media_recorder(body);
    assert!(issues.iter().any(|i| *i == MediaRecorderIssue::ApiDetected));
}

#[test]
fn detects_media_recorder_lowercase() {
    let body = "var mediaRecorder = new Object();";
    let issues = analyze_media_recorder(body);
    assert!(issues.iter().any(|i| *i == MediaRecorderIssue::ApiDetected));
}

#[test]
fn detects_surveillance() {
    let body = "new MediaRecorder(stream); navigator.mediaDevices.getUserMedia(c); fetch('/upload');";
    let issues = analyze_media_recorder(body);
    assert!(issues.iter().any(|i| *i == MediaRecorderIssue::SurveillanceRisk));
}

#[test]
fn no_surveillance_without_network() {
    let body = "new MediaRecorder(stream); navigator.mediaDevices.getUserMedia(c);";
    let issues = analyze_media_recorder(body);
    assert!(!issues.iter().any(|i| *i == MediaRecorderIssue::SurveillanceRisk));
}

#[test]
fn detects_silent_recording() {
    let body = "new MediaRecorder(stream); recorder.start(1000);";
    let issues = analyze_media_recorder(body);
    assert!(issues.iter().any(|i| *i == MediaRecorderIssue::SilentRecording));
}

#[test]
fn no_silent_with_notification() {
    let body = "new MediaRecorder(stream); recorder.start(1000); showNotification('Recording'); notification.show();";
    let issues = analyze_media_recorder(body);
    assert!(!issues.iter().any(|i| *i == MediaRecorderIssue::SilentRecording));
}

#[test]
fn detects_data_exfiltration() {
    let body = "new MediaRecorder(s); recorder.ondataavailable = function(e) { upload(e.data); };";
    let issues = analyze_media_recorder(body);
    assert!(issues.iter().any(|i| *i == MediaRecorderIssue::DataExfiltration));
}

#[test]
fn no_exfiltration_without_network() {
    let body = "new MediaRecorder(s); recorder.ondataavailable = function(e) { save(e.data); };";
    let issues = analyze_media_recorder(body);
    assert!(!issues.iter().any(|i| *i == MediaRecorderIssue::DataExfiltration));
}

#[test]
fn detects_unbounded_recording() {
    let body = "new MediaRecorder(stream); recorder.start(1000);";
    let issues = analyze_media_recorder(body);
    assert!(issues.iter().any(|i| *i == MediaRecorderIssue::UnboundedRecording));
}

#[test]
fn no_unbounded_with_stop() {
    let body = "new MediaRecorder(stream); recorder.start(1000); recorder.stop();";
    let issues = analyze_media_recorder(body);
    assert!(!issues.iter().any(|i| *i == MediaRecorderIssue::UnboundedRecording));
}

#[test]
fn all_issues_detected() {
    let body = concat!(
        "new MediaRecorder(stream); ",
        "navigator.mediaDevices.getUserMedia(c); ",
        "fetch('/exfil'); ",
        "recorder.start(1000); ",
        "recorder.ondataavailable = function(e) { upload(e.data); };",
    );
    let issues = analyze_media_recorder(body);
    assert!(issues.contains(&MediaRecorderIssue::ApiDetected));
    assert!(issues.contains(&MediaRecorderIssue::SurveillanceRisk));
    assert!(issues.contains(&MediaRecorderIssue::SilentRecording));
    assert!(issues.contains(&MediaRecorderIssue::DataExfiltration));
    assert!(issues.contains(&MediaRecorderIssue::UnboundedRecording));
}

#[test]
fn severity_values_correct() {
    assert!((media_recorder_severity(&MediaRecorderIssue::ApiDetected) - 2.0).abs() < f64::EPSILON);
    assert!((media_recorder_severity(&MediaRecorderIssue::SurveillanceRisk) - 8.0).abs() < f64::EPSILON);
    assert!((media_recorder_severity(&MediaRecorderIssue::SilentRecording) - 7.5).abs() < f64::EPSILON);
    assert!((media_recorder_severity(&MediaRecorderIssue::DataExfiltration) - 7.0).abs() < f64::EPSILON);
    assert!((media_recorder_severity(&MediaRecorderIssue::UnboundedRecording) - 5.5).abs() < f64::EPSILON);
}

#[test]
fn display_impl_works() {
    assert_eq!(MediaRecorderIssue::ApiDetected.to_string(), "api_detected");
    assert_eq!(MediaRecorderIssue::SurveillanceRisk.to_string(), "surveillance_risk");
    assert_eq!(MediaRecorderIssue::SilentRecording.to_string(), "silent_recording");
    assert_eq!(MediaRecorderIssue::DataExfiltration.to_string(), "data_exfiltration");
    assert_eq!(MediaRecorderIssue::UnboundedRecording.to_string(), "unbounded_recording");
}

#[test]
fn operations_generated_correctly() {
    let issues = vec![MediaRecorderIssue::ApiDetected];
    let mut seq = 0;
    let ops = media_recorder_to_operations(&issues, &mut seq);
    assert_eq!(ops.len(), 1);
    assert_eq!(seq, 1);
}

#[test]
fn operations_increment_sequence() {
    let issues = vec![
        MediaRecorderIssue::ApiDetected,
        MediaRecorderIssue::SurveillanceRisk,
        MediaRecorderIssue::SilentRecording,
    ];
    let mut seq = 5;
    let ops = media_recorder_to_operations(&issues, &mut seq);
    assert_eq!(ops.len(), 3);
    assert_eq!(seq, 8);
}

#[test]
fn detects_get_display_media() {
    let body = "new MediaRecorder(stream); navigator.mediaDevices.getDisplayMedia(c); fetch('/save');";
    let issues = analyze_media_recorder(body);
    assert!(issues.iter().any(|i| *i == MediaRecorderIssue::SurveillanceRisk));
}
