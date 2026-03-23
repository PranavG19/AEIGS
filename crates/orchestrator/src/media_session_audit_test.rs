use crate::media_session_audit::*;

#[test]
fn no_media_session_no_issues() {
    assert!(analyze_media_session("<html><body>hello</body></html>").is_empty());
}

#[test]
fn detects_api_navigator() {
    let body = r#"<script>navigator.mediaSession.metadata = new MediaMetadata({});</script>"#;
    let issues = analyze_media_session(body);
    assert!(issues.contains(&MediaSessionIssue::ApiDetected));
}

#[test]
fn detects_api_class() {
    let body = r#"<script>if ('MediaSession' in navigator) {}</script>"#;
    let issues = analyze_media_session(body);
    assert!(issues.contains(&MediaSessionIssue::ApiDetected));
}

#[test]
fn detects_metadata_spoofing() {
    let body = r#"<script>
        navigator.mediaSession.metadata = new MediaMetadata({
            title: "Fake Bank Alert", artist: "Security"
        });
    </script>"#;
    let issues = analyze_media_session(body);
    assert!(issues.contains(&MediaSessionIssue::MetadataSpoofing));
}

#[test]
fn detects_action_hijacking() {
    let body = r#"<script>
        navigator.mediaSession.setActionHandler("play", () => {
            window.location = "https://evil.com";
        });
    </script>"#;
    let issues = analyze_media_session(body);
    assert!(issues.contains(&MediaSessionIssue::ActionHijacking));
}

#[test]
fn no_hijacking_without_handler() {
    let body = r#"<script>navigator.mediaSession.metadata = new MediaMetadata({});</script>"#;
    let issues = analyze_media_session(body);
    assert!(!issues.contains(&MediaSessionIssue::ActionHijacking));
}

#[test]
fn detects_external_artwork() {
    let body = r#"<script>
        navigator.mediaSession.metadata = new MediaMetadata({
            artwork: [{src: "https://tracker.com/pixel.png"}]
        });
    </script>"#;
    let issues = analyze_media_session(body);
    assert!(issues.contains(&MediaSessionIssue::ExternalArtwork));
}

#[test]
fn no_external_without_url() {
    let body = r#"<script>
        navigator.mediaSession.metadata = new MediaMetadata({
            artwork: [{src: "/local/art.png"}]
        });
    </script>"#;
    let issues = analyze_media_session(body);
    assert!(!issues.contains(&MediaSessionIssue::ExternalArtwork));
}

#[test]
fn detects_silent_playback() {
    let body = r#"<script>
        const a = new Audio("/track.mp3");
        a.volume = 0;
        navigator.mediaSession.metadata = new MediaMetadata({title: "bg"});
    </script>"#;
    let issues = analyze_media_session(body);
    assert!(issues.contains(&MediaSessionIssue::SilentPlayback));
}

#[test]
fn detects_position_tracking() {
    let body = r#"<script>
        navigator.mediaSession.setPositionState({duration: 300, position: 10});
    </script>"#;
    let issues = analyze_media_session(body);
    assert!(issues.contains(&MediaSessionIssue::PositionTracking));
}

#[test]
fn no_position_without_call() {
    let body = r#"<script>navigator.mediaSession.metadata = new MediaMetadata({});</script>"#;
    let issues = analyze_media_session(body);
    assert!(!issues.contains(&MediaSessionIssue::PositionTracking));
}

#[test]
fn severity_hijacking_highest() {
    assert_eq!(
        media_session_severity(&MediaSessionIssue::ActionHijacking),
        6.5
    );
}

#[test]
fn severity_detected_lowest() {
    assert_eq!(media_session_severity(&MediaSessionIssue::ApiDetected), 2.0);
}

#[test]
fn to_operations_creates_entries() {
    let issues = vec![
        MediaSessionIssue::ApiDetected,
        MediaSessionIssue::ActionHijacking,
    ];
    let mut seq = 0;
    let ops = media_session_to_operations(&issues, &mut seq);
    assert_eq!(ops.len(), 2);
    assert_eq!(seq, 2);
}

#[test]
fn display_variants() {
    assert_eq!(MediaSessionIssue::ApiDetected.to_string(), "api_detected");
    assert_eq!(
        MediaSessionIssue::MetadataSpoofing.to_string(),
        "metadata_spoofing"
    );
    assert_eq!(
        MediaSessionIssue::ActionHijacking.to_string(),
        "action_hijacking"
    );
    assert_eq!(
        MediaSessionIssue::ExternalArtwork.to_string(),
        "external_artwork"
    );
    assert_eq!(
        MediaSessionIssue::SilentPlayback.to_string(),
        "silent_playback"
    );
    assert_eq!(
        MediaSessionIssue::PositionTracking.to_string(),
        "position_tracking"
    );
}

#[test]
fn empty_body_no_issues() {
    assert!(analyze_media_session("").is_empty());
}
